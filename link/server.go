package link

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	linkv1 "github.com/incantery/rook-host/gen/rook/link/v1"
	"github.com/incantery/rook-host/gen/rook/link/v1/linkv1connect"
	"github.com/incantery/rook-host/identity"
	"github.com/incantery/rook-host/pairing"
	"github.com/incantery/rook-host/projection"
	"github.com/incantery/rook-host/registry"
)

// ProtocolVersion is what this generation of the link rail speaks.
const ProtocolVersion = "rook-link/1"

// bearerPrefix marks a link session token in the Authorization header.
const bearerPrefix = "Bearer link-"

// Options configures a Server. Identity, Registry, and Executor are
// required; the rest default sensibly.
type Options struct {
	Identity *identity.Identity
	Registry *registry.Registry
	Pairing  *pairing.Manager
	Executor Executor
	// HostName is the user-visible name in GetHostInfo ("Seth's MacBook
	// Pro"). Display only.
	HostName string
	// RequestedTTL for heartbeats on WatchStatus. Well under the ~100s
	// idle cutoff proxies apply to a silent body. 0 = 25s.
	Heartbeat time.Duration
	// Now is the clock, for tests. nil = time.Now.
	Now func() time.Time
}

// Server implements rook.link.v1: HostService (pre-session) and
// LinkService (token-gated). It owns protocol truth and no machine
// truth — snapshots come in through Publish, effects go out through
// the Executor.
type Server struct {
	id        *identity.Identity
	reg       *registry.Registry
	pairs     *pairing.Manager
	exec      Executor
	hostName  string
	heartbeat time.Duration
	now       func() time.Time

	hub    *hub
	tokens *tokens
	nonces *nonces
}

// NewServer wires a Server. Panics on missing requirements — this is
// construction-time wiring, not runtime input.
func NewServer(o Options) *Server {
	if o.Identity == nil || o.Registry == nil || o.Executor == nil {
		panic("link: Options needs Identity, Registry, and Executor")
	}
	if o.Pairing == nil {
		o.Pairing = &pairing.Manager{}
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = 25 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Server{
		id:        o.Identity,
		reg:       o.Registry,
		pairs:     o.Pairing,
		exec:      o.Executor,
		hostName:  o.HostName,
		heartbeat: o.Heartbeat,
		now:       o.Now,
		hub:       newHub(),
		tokens:    newTokens(),
		nonces:    newNonces(),
	}
}

// Handler mounts both services on one mux — the transport layer (TLS
// listener, or a test's httptest server) serves this.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(linkv1connect.NewHostServiceHandler(s))
	mux.Handle(linkv1connect.NewLinkServiceHandler(s))
	return mux
}

// Publish makes a snapshot current and fans it out to watchers. The
// embedding host calls this on its own cadence; the seq lets any
// surface collapse races to newest-wins. The host's identity is
// stamped here — the embedder supplies machine truth, the server
// supplies who the machine IS.
func (s *Server) Publish(status projection.Status) uint64 {
	status.HostID = s.id.HostID()
	return s.hub.publish(status, s.now())
}

// RevokeDevice is the whole revocation, in one breath: tombstone in
// the registry, every session token dropped, every open stream
// cancelled. The device's next RPC — and its current ones — fail.
func (s *Server) RevokeDevice(deviceID string) error {
	if err := s.reg.Revoke(deviceID, s.now()); err != nil {
		return err
	}
	s.tokens.dropDevice(deviceID)
	s.hub.dropDevice(deviceID)
	return nil
}

// ---------------------------------------------------------------------
// HostService: the pre-session surface.

func (s *Server) GetHostInfo(ctx context.Context, req *connect.Request[linkv1.GetHostInfoRequest]) (*connect.Response[linkv1.GetHostInfoResponse], error) {
	return connect.NewResponse(&linkv1.GetHostInfoResponse{
		HostId:           s.id.HostID(),
		HostName:         s.hostName,
		TrustDomainId:    s.id.TrustDomainID,
		ProtocolVersions: []string{ProtocolVersion},
		PairingOpen:      s.pairs.OpenNow(s.now()),
		HostPublicKey:    s.id.PublicKey(),
	}), nil
}

func (s *Server) Pair(ctx context.Context, req *connect.Request[linkv1.PairRequest]) (*connect.Response[linkv1.PairResponse], error) {
	m := req.Msg
	if m.ProtocolVersion != ProtocolVersion {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("host speaks %s, device sent %q", ProtocolVersion, m.ProtocolVersion))
	}
	if len(m.DevicePublicKey) != ed25519.PublicKeySize {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device key must be 32 bytes of Ed25519"))
	}
	devPub := ed25519.PublicKey(m.DevicePublicKey)

	// Proof before secret: a bad proof must not burn the human's window.
	if !identity.VerifyPairProof(devPub, s.id.HostID(), m.PairingSecret, m.Proof) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("pairing proof does not verify"))
	}
	if !s.pairs.Redeem(m.PairingSecret, s.now()) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("no open pairing window for that secret"))
	}

	deviceID := identity.DeviceIDFor(devPub)
	caps := m.RequestedCapabilities
	if len(caps) == 0 {
		caps = registry.DefaultCapabilities
	}
	d := registry.Device{
		ID:           deviceID,
		Name:         clipDisplay(m.DeviceName),
		Model:        clipDisplay(m.DeviceModel),
		PublicKey:    append([]byte(nil), m.DevicePublicKey...),
		Capabilities: caps,
		PairedAt:     s.now().UTC(),
	}
	if err := s.reg.Add(d); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// A re-pair replaced any prior registration for this key; sessions
	// and streams minted under the old one end with it. The device is
	// mid-pairing, so the cost is one Challenge it was about to run
	// anyway.
	s.tokens.dropDevice(deviceID)
	s.hub.dropDevice(deviceID)
	granted, _ := s.reg.Get(deviceID)
	return connect.NewResponse(&linkv1.PairResponse{
		DeviceId:            deviceID,
		HostId:              s.id.HostID(),
		TrustDomainId:       s.id.TrustDomainID,
		HostPublicKey:       s.id.PublicKey(),
		GrantedCapabilities: granted.Capabilities,
	}), nil
}

func (s *Server) Challenge(ctx context.Context, req *connect.Request[linkv1.ChallengeRequest]) (*connect.Response[linkv1.ChallengeResponse], error) {
	d, ok := s.reg.Get(req.Msg.DeviceId)
	if !ok || d.Revoked() {
		// One error for both: a prober learns "not pairable", never which.
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("unknown or revoked device"))
	}
	n, exp, err := s.nonces.mint(d.ID, s.now())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&linkv1.ChallengeResponse{
		Nonce:     n,
		ExpiresAt: timestamppb.New(exp),
	}), nil
}

func (s *Server) Authenticate(ctx context.Context, req *connect.Request[linkv1.AuthenticateRequest]) (*connect.Response[linkv1.AuthenticateResponse], error) {
	m := req.Msg
	d, ok := s.reg.Get(m.DeviceId)
	if !ok || d.Revoked() {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("unknown or revoked device"))
	}
	// Consume before verify: a failed signature burns the challenge too,
	// so nothing is learnable by retrying against the same nonce.
	if !s.nonces.consume(m.Nonce, d.ID, s.now()) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("challenge is unknown, expired, or not yours"))
	}
	if !identity.VerifyAuth(d.Key(), s.id.HostID(), d.ID, m.Nonce, m.Signature) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("challenge signature does not verify"))
	}
	tok, exp, err := s.tokens.mint(d.ID, s.now())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.reg.Touch(d.ID, s.now())
	return connect.NewResponse(&linkv1.AuthenticateResponse{
		SessionToken:  []byte(tok),
		ExpiresAt:     timestamppb.New(exp),
		Capabilities:  d.Capabilities,
		TrustDomainId: s.id.TrustDomainID,
	}), nil
}

// ---------------------------------------------------------------------
// LinkService: the session surface. Every method authorizes live —
// token to device, device to capability, registry consulted per call.

// authorize resolves the caller and checks the capability against the
// live registry. The registry check is the revocation path for unary
// calls; streams additionally hold a cancellation handle in the hub.
func (s *Server) authorize(header http.Header, capability string) (string, error) {
	auth := header.Get("Authorization")
	if !strings.HasPrefix(auth, bearerPrefix) {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("no link session token"))
	}
	deviceID := s.tokens.resolve(strings.TrimPrefix(auth, bearerPrefix), s.now())
	if deviceID == "" {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("session token is unknown or expired"))
	}
	if err := s.reg.Allowed(deviceID, capability); err != nil {
		return "", connect.NewError(connect.CodePermissionDenied, err)
	}
	return deviceID, nil
}

func (s *Server) GetStatus(ctx context.Context, req *connect.Request[linkv1.GetStatusRequest]) (*connect.Response[linkv1.GetStatusResponse], error) {
	if _, err := s.authorize(req.Header(), registry.CapStatusRead); err != nil {
		return nil, err
	}
	cur, at, seq := s.hub.snapshot()
	return connect.NewResponse(&linkv1.GetStatusResponse{
		Status: statusToProto(cur, at),
		Seq:    seq,
	}), nil
}

func (s *Server) WatchStatus(ctx context.Context, req *connect.Request[linkv1.WatchStatusRequest], stream *connect.ServerStream[linkv1.WatchStatusResponse]) error {
	deviceID, err := s.authorize(req.Header(), registry.CapStatusRead)
	if err != nil {
		return err
	}
	sub, opening := s.hub.subscribe(deviceID)
	defer s.hub.unsubscribe(sub)

	// The opening snapshot, always: anything published while the stream
	// was down raced the subscription, and this closes the gap.
	if err := stream.Send(&linkv1.WatchStatusResponse{
		Kind:   linkv1.WatchStatusResponse_KIND_SNAPSHOT,
		Status: statusToProto(opening.status, opening.at),
		Seq:    opening.seq,
	}); err != nil {
		return err
	}

	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sub.gone:
			// Revoked mid-stream. Name the reason; the surface should
			// stop reconnecting.
			return connect.NewError(connect.CodePermissionDenied, errors.New("device revoked"))
		case f := <-sub.updates:
			if err := stream.Send(&linkv1.WatchStatusResponse{
				Kind:   linkv1.WatchStatusResponse_KIND_SNAPSHOT,
				Status: statusToProto(f.status, f.at),
				Seq:    f.seq,
			}); err != nil {
				return err
			}
		case <-ticker.C:
			if err := stream.Send(&linkv1.WatchStatusResponse{
				Kind: linkv1.WatchStatusResponse_KIND_HEARTBEAT,
			}); err != nil {
				return err
			}
		}
	}
}

func (s *Server) SubmitAnswer(ctx context.Context, req *connect.Request[linkv1.SubmitAnswerRequest]) (*connect.Response[linkv1.SubmitAnswerResponse], error) {
	deviceID, err := s.authorize(req.Header(), registry.CapAgentAnswer)
	if err != nil {
		return nil, err
	}
	a, err := projection.ValidAnswer(req.Msg.AskId, req.Msg.Text)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	out := s.exec.Answer(ctx, a)
	s.reg.Touch(deviceID, s.now())
	return connect.NewResponse(&linkv1.SubmitAnswerResponse{
		Disposition: dispositionToProto(out.Disposition),
		Note:        out.Note,
	}), nil
}

func (s *Server) SubmitCommand(ctx context.Context, req *connect.Request[linkv1.SubmitCommandRequest]) (*connect.Response[linkv1.SubmitCommandResponse], error) {
	deviceID, err := s.authorize(req.Header(), registry.CapAgentCommand)
	if err != nil {
		return nil, err
	}
	// The SAME validation and natural keys as the cloud rail — which is
	// exactly why a command arriving over both rails is one command.
	c, err := projection.ValidCommand(kindFromProto(req.Msg.Kind), req.Msg.SessionId, req.Msg.Workspace, req.Msg.Prompt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	out := s.exec.Execute(ctx, c)
	s.reg.Touch(deviceID, s.now())
	return connect.NewResponse(&linkv1.SubmitCommandResponse{
		CommandId:   c.ID,
		Disposition: dispositionToProto(out.Disposition),
		Note:        out.Note,
	}), nil
}

// clipDisplay bounds the display-only strings a device supplies about
// itself, the same discipline the projection clamps apply.
func clipDisplay(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	for i := max; i > 0; i-- {
		if s[i]&0xC0 != 0x80 {
			return s[:i]
		}
	}
	return ""
}
