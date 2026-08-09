// Package edgeclient is the device side of the Cloud–IDE edge protocol:
// register, sync, ack, execute, report. The real IDE carries a durable
// SQLite journal between those verbs (backlog item 17, in the IDE's own
// repo); this client is the honest stateless subset — enough to prove
// the wire end-to-end and to play a device in demos and tests.
//
// Statelessness leans on the protocol's own guarantees rather than
// fighting them. Device sequences are re-derived from the server's ack
// cursor on every pass, so a restarted client continues where the Cloud
// says it was. If a crash left recorded-but-unacked sequences above the
// cursor, a reused sequence number's receipt is dropped by the server
// (ON CONFLICT DO NOTHING) — and that is safe HERE because the effect a
// receipt witnesses is idempotent by construction and applied before
// the receipt. A journal-backed IDE never reuses sequences; a stateless
// client survives doing so.
package edgeclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	edgev1 "github.com/incantery/rook-host/gen/rook/edge/v1"
	"github.com/incantery/rook-host/gen/rook/edge/v1/edgev1connect"
	"github.com/incantery/rook-host/edge"
	"github.com/incantery/rook-host/edgesign"
)

// Executor turns a delivered command into a local outcome. The command
// arrives fully typed; the executor answers with the ledger's status
// vocabulary (succeeded | failed | rejected) and a structured result.
// It must not panic and it must not block forever — the sync pass is
// serial on purpose, mirroring the IDE's one-journal discipline.
type Executor func(ctx context.Context, cmd *edgev1.EdgeCommand) (status string, resultJSON []byte)

// AgentUpdate is a session-lifecycle fact observed while handling a
// command: the session started, progressed, claimed completion. The
// real IDE's adapter observes these asynchronously and journals them as
// they happen; this stateless client can only report what it learned
// during the execute call, which is exactly enough for a simulator.
type AgentUpdate struct {
	SessionID string
	Kind      string // the AgentEvent vocabulary; the cloud refuses strangers
	Summary   string
	DataJSON  []byte
}

// Client drives the protocol against one authenticated machine
// identity. RPC carries the bearer token (see NewRPC); nothing in this
// struct knows the token exists.
type Client struct {
	RPC     edgev1connect.EdgeServiceClient
	Execute Executor
	Log     *slog.Logger // nil = slog.Default()

	// Agent, when set, is consulted after each executed command for
	// session facts to report alongside the receipt. The receipt goes
	// first in the journal order — a session may not be spoken of
	// before the receipt that introduced it.
	Agent func(cmd *edgev1.EdgeCommand, status string, resultJSON []byte) []AgentUpdate

	// Key signs every submitted event (§13.5). Nil = unsigned events —
	// the real IDE holds this in the OS keystore; this client generates
	// one per process, which is rotation on every restart and exactly
	// as much as a stateless stand-in should promise.
	Key ed25519.PrivateKey

	// cloudKey arrives with registration. Once known, a command whose
	// cloud_signature does not verify is rejected without executing —
	// that is the entire point of the key.
	cloudKey ed25519.PublicKey
}

// NewRPC builds the Connect client that authenticates every call with
// the machine bearer token from /api/machines. The token rides only in
// the Authorization header — never in logs, never in argv.
func NewRPC(httpClient connect.HTTPClient, baseURL, token string) edgev1connect.EdgeServiceClient {
	return edgev1connect.NewEdgeServiceClient(httpClient, baseURL,
		connect.WithInterceptors(bearer(token)))
}

// bearer stamps the token on unary AND streaming calls. A
// UnaryInterceptorFunc would silently skip streams, and the wake stream
// would knock on the gate with no credential — the kind of bug that
// presents as "streaming never works in production, only in tests whose
// server skips auth".
type bearer string

func (b bearer) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+string(b))
		return next(ctx, req)
	}
}

func (b bearer) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+string(b))
		return conn
	}
}

func (b bearer) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// Register announces the device, offering its verification key and
// learning the cloud's. The response's device ID is the machine ID the
// token resolved to — the client learns its own identity from the
// server, never the other way around.
func (c *Client) Register(ctx context.Context, name, platform string, capabilities []string) (string, error) {
	req := &edgev1.RegisterDeviceRequest{
		ProtocolVersion: edge.ProtocolVersion,
		DeviceName:      name,
		Platform:        platform,
		Capabilities:    capabilities,
	}
	if c.Key != nil {
		req.PublicKey = c.Key.Public().(ed25519.PublicKey)
	}
	res, err := c.RPC.RegisterDevice(ctx, connect.NewRequest(req))
	if err != nil {
		return "", fmt.Errorf("register: %w", err)
	}
	c.cloudKey = res.Msg.CloudPublicKey
	return res.Msg.DeviceId, nil
}

// CloudSigning reports whether registration delivered a cloud key —
// i.e. whether received commands are being verified before execution.
func (c *Client) CloudSigning() bool { return len(c.cloudKey) > 0 }

// SyncReport is what one pass did, for the caller's log line.
type SyncReport struct {
	Commands    int      // commands the server offered this pass
	Reported    int      // result events submitted
	AckedSeq    uint64   // server's contiguous cursor after the pass
	PollSeconds uint32   // server's idle-poll hint
	Rejections  []string // per-event refusals, verbatim
}

// SyncOnce runs one full pass: pull pending commands, ack each (the
// journal-write stand-in), execute serially, submit the results as one
// batch. Re-running converges: a command already resolved stops being
// offered, and a re-reported outcome dedupes on the cloud's ledger.
func (c *Client) SyncOnce(ctx context.Context) (SyncReport, error) {
	sync, err := c.RPC.SyncEdge(ctx, connect.NewRequest(&edgev1.SyncEdgeRequest{
		ProtocolVersion: edge.ProtocolVersion,
	}))
	if err != nil {
		return SyncReport{}, fmt.Errorf("sync: %w", err)
	}
	report := SyncReport{
		Commands:    len(sync.Msg.Commands),
		AckedSeq:    sync.Msg.AckedDeviceSequence,
		PollSeconds: sync.Msg.PollIntervalSeconds,
	}

	seq := sync.Msg.AckedDeviceSequence
	var events []*edgev1.EdgeEvent
	for _, cmd := range sync.Msg.Commands {
		// Ack first: in the real IDE this marks "durably journaled", and
		// keeping the order here means the traffic shape matches.
		if _, err := c.RPC.AckCommand(ctx, connect.NewRequest(&edgev1.AckCommandRequest{
			CommandId: cmd.CommandId,
		})); err != nil {
			return report, fmt.Errorf("ack %s: %w", cmd.CommandId, err)
		}
		var status string
		var resultJSON []byte
		if reason := c.refuse(cmd); reason != "" {
			// Failed verification: rejected without executing (§13.5,
			// §12.2). The rejection is itself a result — the run hears
			// "rejected" instead of waiting on a command this device
			// won't touch.
			c.log().Warn("refusing command without executing", "command", cmd.CommandId, "reason", reason)
			data, _ := json.Marshal(map[string]string{"reason": reason})
			status, resultJSON = "rejected", data
		} else {
			status, resultJSON = c.Execute(ctx, cmd)
		}
		seq++
		ev, err := resultEvent(cmd, seq, status, resultJSON)
		if err != nil {
			return report, fmt.Errorf("event for %s: %w", cmd.CommandId, err)
		}
		if c.Key != nil {
			edgesign.SignEvent(c.Key, ev)
		}
		events = append(events, ev)
		if c.Agent == nil {
			continue
		}
		for i, upd := range c.Agent(cmd, status, resultJSON) {
			seq++
			aev, err := agentEvent(cmd, seq, i, upd)
			if err != nil {
				return report, fmt.Errorf("agent event for %s: %w", cmd.CommandId, err)
			}
			if c.Key != nil {
				edgesign.SignEvent(c.Key, aev)
			}
			events = append(events, aev)
		}
	}
	if len(events) == 0 {
		return report, nil
	}

	res, err := c.RPC.SubmitEvents(ctx, connect.NewRequest(&edgev1.SubmitEventsRequest{Events: events}))
	if err != nil {
		return report, fmt.Errorf("submit: %w", err)
	}
	report.Reported = len(events)
	report.AckedSeq = res.Msg.AckedDeviceSequence
	for _, rej := range res.Msg.Rejections {
		report.Rejections = append(report.Rejections,
			fmt.Sprintf("seq %d: %s", rej.DeviceSequence, rej.Reason))
	}
	return report, nil
}

// refuse is the device's pre-execution checklist; a non-empty return is
// the refusal reason. Envelope signature first (§13.5), then the ledger
// payload's digest when the bytes rode along, then the full grant
// checklist when the command spends one (§12.2) — each check assumes
// the previous held, which is why the order is fixed.
func (c *Client) refuse(cmd *edgev1.EdgeCommand) string {
	if c.cloudKey != nil && !edgesign.VerifyCommand(c.cloudKey, cmd) {
		return "cloud_signature does not verify"
	}
	if len(cmd.LedgerPayload) > 0 {
		if _, err := edgesign.VerifiedLedgerPayload(cmd); err != nil {
			return err.Error()
		}
	}
	if cmd.ApprovalGrantId != "" {
		if _, err := edgesign.VerifyCommandGrant(c.cloudKey, cmd, time.Now()); err != nil {
			return "grant refused: " + err.Error()
		}
	}
	return ""
}

// Follow polls until ctx ends, at the server's suggested interval —
// with the wake stream, when the server offers one, cutting the wait
// short the moment durable work appears. The poll never stops being the
// ceiling: a dead stream costs latency, not commands. Transport errors
// are logged and retried — a device does not give up on its cloud
// because one poll failed — but an authentication refusal ends the
// loop: a revoked token never fixes itself.
func (c *Client) Follow(ctx context.Context) error {
	wake := make(chan struct{}, 1)
	go c.watch(ctx, wake)
	for {
		report, err := c.SyncOnce(ctx)
		interval := time.Duration(max(report.PollSeconds, 1)) * time.Second
		switch {
		case connect.CodeOf(err) == connect.CodeUnauthenticated:
			return err
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.log().Warn("sync pass failed; will retry", "err", err)
		default:
			if report.Commands > 0 || len(report.Rejections) > 0 {
				c.log().Info("sync pass",
					"commands", report.Commands, "reported", report.Reported,
					"acked_seq", report.AckedSeq, "rejections", report.Rejections)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		case <-wake:
		}
	}
}

// watch holds the wake stream, nudging the Follow loop on every wake —
// including the LISTENING greeting, because anything minted while the
// stream was down raced the subscription and deserves a catch-up sync.
// The stream is only ever an accelerator: failures back off and retry,
// an Unimplemented or Unauthenticated answer retires the watcher for
// good, and the poll loop never learns any of this happened.
func (c *Client) watch(ctx context.Context, wake chan<- struct{}) {
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := c.RPC.WatchEdge(ctx, connect.NewRequest(&edgev1.WatchEdgeRequest{
			ProtocolVersion: edge.ProtocolVersion,
		}))
		if err == nil {
			for stream.Receive() {
				backoff = time.Second // a live stream resets the clock
				switch stream.Msg().Kind {
				case edgev1.WatchEdgeResponse_KIND_WAKE, edgev1.WatchEdgeResponse_KIND_LISTENING:
					select {
					case wake <- struct{}{}:
					default: // a pending nudge needs no second one
					}
				}
			}
			err = stream.Err()
		}
		switch connect.CodeOf(err) {
		case connect.CodeUnimplemented:
			c.log().Info("wake stream not offered; polling only")
			return
		case connect.CodeUnauthenticated:
			return // the poll loop is about to learn the same thing
		}
		if ctx.Err() != nil {
			return
		}
		c.log().Warn("wake stream down; will reconnect", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// agentEvent wraps a session fact in the wire envelope. The ID derives
// from the causing command and the update's position — a replayed
// execute pass emits the same identities, so the cloud's dedupe treats
// the replay as the convergence it is.
func agentEvent(cmd *edgev1.EdgeCommand, seq uint64, i int, upd AgentUpdate) (*edgev1.EdgeEvent, error) {
	if upd.SessionID == "" || upd.Kind == "" {
		return nil, errors.New("agent update needs a session and a kind")
	}
	payload, err := anypb.New(&edgev1.AgentEvent{
		SessionId: upd.SessionID,
		Kind:      upd.Kind,
		Summary:   upd.Summary,
		DataJson:  upd.DataJSON,
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload.Value)
	return &edgev1.EdgeEvent{
		EventId:        fmt.Sprintf("devevt_%s_agent_%d_%s", cmd.CommandId, i, upd.Kind),
		DeviceId:       cmd.DeviceId,
		DeviceSequence: seq,
		CommandId:      cmd.CommandId,
		Type:           edge.EventTypeAgentEvent,
		OccurredAt:     timestamppb.Now(),
		Payload:        payload,
		PayloadDigest:  digest[:],
	}, nil
}

// resultEvent wraps an outcome in the wire envelope. The event ID is
// derived from cause and outcome — the same convention as the cloud's
// resolved-event IDs — so a re-report of the same outcome converges
// everywhere, while a contradiction gets a distinct identity and dies
// on the cloud's ledger check instead of blending in.
func resultEvent(cmd *edgev1.EdgeCommand, seq uint64, status string, resultJSON []byte) (*edgev1.EdgeEvent, error) {
	if status == "" {
		return nil, errors.New("executor returned an empty status")
	}
	payload, err := anypb.New(&edgev1.CommandResult{
		CommandId:  cmd.CommandId,
		Status:     status,
		ResultJson: resultJSON,
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload.Value)
	return &edgev1.EdgeEvent{
		EventId:        fmt.Sprintf("devevt_%s_%s", cmd.CommandId, status),
		DeviceId:       cmd.DeviceId,
		DeviceSequence: seq,
		CommandId:      cmd.CommandId,
		Type:           edge.EventTypeCommandResult,
		OccurredAt:     timestamppb.Now(),
		Payload:        payload,
		PayloadDigest:  digest[:],
		// device_signature stays empty until device identity keys land
		// (backlog item 20) — same stance as the cloud's signature field.
	}, nil
}
