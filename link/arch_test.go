// The §27 architecture tests: the guarantees that keep the link rail
// honest, exercised over plain HTTP with no TLS and no Bonjour —
// which is itself the transport-independence proof. Anything these
// tests catch is a protocol regression, not a style problem.
package link_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	linkv1 "github.com/incantery/rook-host/gen/rook/link/v1"
	"github.com/incantery/rook-host/gen/rook/link/v1/linkv1connect"
	"github.com/incantery/rook-host/identity"
	"github.com/incantery/rook-host/link"
	"github.com/incantery/rook-host/pairing"
	"github.com/incantery/rook-host/projection"
	"github.com/incantery/rook-host/registry"
)

// fakeExec records what reached the keyboard and answers Delivered,
// or Duplicate for keys it has seen — a two-line cmdjournal.
type fakeExec struct {
	mu       sync.Mutex
	answers  []projection.Answer
	commands []projection.Command
	seen     map[string]bool
}

func newFakeExec() *fakeExec { return &fakeExec{seen: map[string]bool{}} }

func (f *fakeExec) Answer(_ context.Context, a projection.Answer) link.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen["ask:"+a.AskID] {
		return link.Outcome{Disposition: link.Duplicate}
	}
	f.seen["ask:"+a.AskID] = true
	f.answers = append(f.answers, a)
	return link.Outcome{Disposition: link.Delivered}
}

func (f *fakeExec) Execute(_ context.Context, c projection.Command) link.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen["cmd:"+c.ID] {
		return link.Outcome{Disposition: link.Duplicate}
	}
	f.seen["cmd:"+c.ID] = true
	f.commands = append(f.commands, c)
	return link.Outcome{Disposition: link.Delivered}
}

// fakePanes records the watcher-count edges the hub drives.
type fakePanes struct {
	mu     sync.Mutex
	opens  map[string]int
	closes map[string]int
}

func newFakePanes() *fakePanes {
	return &fakePanes{opens: map[string]int{}, closes: map[string]int{}}
}

func (f *fakePanes) Open(sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens[sessionID]++
	return nil
}

func (f *fakePanes) Close(sessionID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes[sessionID]++
}

func (f *fakePanes) counts(sessionID string) (opens, closes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens[sessionID], f.closes[sessionID]
}

// fakeDigests serves canned membrane artifacts by session id.
type fakeDigests map[string]projection.Digest

func (f fakeDigests) Digest(sessionID string) (projection.Digest, bool) {
	d, ok := f[sessionID]
	return d, ok
}

// rig is one host under test plus everything a test pokes at.
type rig struct {
	t       *testing.T
	srv     *link.Server
	id      *identity.Identity
	reg     *registry.Registry
	pairs   *pairing.Manager
	exec    *fakeExec
	panes   *fakePanes
	digests fakeDigests
	ts      *httptest.Server
	now     time.Time
	nowMu   sync.Mutex
	host    linkv1connect.HostServiceClient
	client  linkv1connect.LinkServiceClient // unauthenticated
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	id, err := identity.LoadOrCreate(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, id: id, reg: reg, pairs: &pairing.Manager{}, exec: newFakeExec(), panes: newFakePanes(), digests: fakeDigests{}, now: time.Now()}
	r.srv = link.NewServer(link.Options{
		Identity:  id,
		Registry:  reg,
		Pairing:   r.pairs,
		Executor:  r.exec,
		Panes:     r.panes,
		Digests:   r.digests,
		HostName:  "test host",
		Heartbeat: 50 * time.Millisecond,
		Now: func() time.Time {
			r.nowMu.Lock()
			defer r.nowMu.Unlock()
			return r.now
		},
	})
	// Plain HTTP, no TLS, no Bonjour: the whole protocol must run over
	// any pipe that carries requests.
	r.ts = httptest.NewServer(r.srv.Handler())
	t.Cleanup(r.ts.Close)
	r.host = linkv1connect.NewHostServiceClient(r.ts.Client(), r.ts.URL)
	r.client = linkv1connect.NewLinkServiceClient(r.ts.Client(), r.ts.URL)
	return r
}

func (r *rig) advance(d time.Duration) {
	r.nowMu.Lock()
	defer r.nowMu.Unlock()
	r.now = r.now.Add(d)
}

// device is a fake phone: a key and its session.
type device struct {
	pub   ed25519.PublicKey
	key   ed25519.PrivateKey
	id    string
	token string
	link  linkv1connect.LinkServiceClient // authenticated
}

// pair runs the full ceremony: window, secret, proof, Pair.
func (r *rig) pair(caps ...string) *device {
	r.t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		r.t.Fatal(err)
	}
	secret, err := r.pairs.Open(r.now)
	if err != nil {
		r.t.Fatal(err)
	}
	proof := identity.SignPairProof(key, r.id.HostID(), secret, pub)
	res, err := r.host.Pair(context.Background(), connect.NewRequest(&linkv1.PairRequest{
		ProtocolVersion:       link.ProtocolVersion,
		PairingSecret:         secret,
		DevicePublicKey:       pub,
		DeviceName:            "test phone",
		RequestedCapabilities: caps,
		Proof:                 proof,
	}))
	if err != nil {
		r.t.Fatalf("pair: %v", err)
	}
	return &device{pub: pub, key: key, id: res.Msg.DeviceId}
}

// authenticate runs challenge/response and arms the device's client.
func (r *rig) authenticate(d *device) {
	r.t.Helper()
	ch, err := r.host.Challenge(context.Background(), connect.NewRequest(&linkv1.ChallengeRequest{DeviceId: d.id}))
	if err != nil {
		r.t.Fatalf("challenge: %v", err)
	}
	sig := identity.SignAuth(d.key, r.id.HostID(), d.id, ch.Msg.Nonce)
	res, err := r.host.Authenticate(context.Background(), connect.NewRequest(&linkv1.AuthenticateRequest{
		ProtocolVersion: link.ProtocolVersion,
		DeviceId:        d.id,
		Nonce:           ch.Msg.Nonce,
		Signature:       sig,
	}))
	if err != nil {
		r.t.Fatalf("authenticate: %v", err)
	}
	d.token = string(res.Msg.SessionToken)
	d.link = linkv1connect.NewLinkServiceClient(
		&http.Client{Transport: &authed{token: d.token, base: r.ts.Client().Transport}},
		r.ts.URL,
	)
}

type authed struct {
	token string
	base  http.RoundTripper
}

func (a *authed) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer link-"+a.token)
	base := a.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func code(err error) connect.Code {
	if err == nil {
		return 0
	}
	return connect.CodeOf(err)
}

// --- Transport independence: the whole vertical over bare HTTP -------

func TestFullVerticalOverPlainHTTP(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)

	r.srv.Publish(projection.Status{
		Hostname: "mac",
		Workspaces: []projection.Workspace{{
			Name: "rook",
			Agents: []projection.Agent{{
				ID: "sess-1", State: "needs_input", Title: "migration",
				Ask: "ship it?", AskID: "ask-1",
			}},
		}},
	})

	got, err := d.link.GetStatus(context.Background(), connect.NewRequest(&linkv1.GetStatusRequest{}))
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	ag := got.Msg.Status.Workspaces[0].Agents[0]
	if ag.AskId != "ask-1" || ag.State != linkv1.AgentState_AGENT_STATE_NEEDS_INPUT {
		t.Fatalf("projection mangled: %+v", ag)
	}

	ans, err := d.link.SubmitAnswer(context.Background(), connect.NewRequest(&linkv1.SubmitAnswerRequest{
		AskId: "ask-1", Text: "yes, ship it",
	}))
	if err != nil || ans.Msg.Disposition != linkv1.Disposition_DISPOSITION_DELIVERED {
		t.Fatalf("answer: %+v %v", ans, err)
	}
	// The same answer again is a loud duplicate, not a double-type.
	ans2, err := d.link.SubmitAnswer(context.Background(), connect.NewRequest(&linkv1.SubmitAnswerRequest{
		AskId: "ask-1", Text: "yes, ship it",
	}))
	if err != nil || ans2.Msg.Disposition != linkv1.Disposition_DISPOSITION_DUPLICATE {
		t.Fatalf("dup answer: %+v %v", ans2, err)
	}

	cmd, err := d.link.SubmitCommand(context.Background(), connect.NewRequest(&linkv1.SubmitCommandRequest{
		Kind: linkv1.CommandKind_COMMAND_KIND_COMPACT, SessionId: "sess-1",
	}))
	if err != nil || cmd.Msg.CommandId != "compact:sess-1" ||
		cmd.Msg.Disposition != linkv1.Disposition_DISPOSITION_DELIVERED {
		t.Fatalf("command: %+v %v", cmd, err)
	}
	if len(r.exec.answers) != 1 || len(r.exec.commands) != 1 {
		t.Fatalf("keyboard saw %d answers, %d commands", len(r.exec.answers), len(r.exec.commands))
	}
}

// --- Pairing enforcement ---------------------------------------------

func TestUnpairedAndUnauthenticatedAreRefused(t *testing.T) {
	r := newRig(t)
	r.srv.Publish(projection.Status{Hostname: "mac"})

	// No token at all.
	_, err := r.client.GetStatus(context.Background(), connect.NewRequest(&linkv1.GetStatusRequest{}))
	if code(err) != connect.CodeUnauthenticated {
		t.Fatalf("bare GetStatus: %v", err)
	}
	// Garbage token.
	bad := linkv1connect.NewLinkServiceClient(
		&http.Client{Transport: &authed{token: "not-a-token"}}, r.ts.URL)
	_, err = bad.GetStatus(context.Background(), connect.NewRequest(&linkv1.GetStatusRequest{}))
	if code(err) != connect.CodeUnauthenticated {
		t.Fatalf("garbage token: %v", err)
	}
}

func TestPairingWindowDiscipline(t *testing.T) {
	r := newRig(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)

	pairReq := func(secret string) *connect.Request[linkv1.PairRequest] {
		return connect.NewRequest(&linkv1.PairRequest{
			ProtocolVersion: link.ProtocolVersion,
			PairingSecret:   secret,
			DevicePublicKey: pub,
			Proof:           identity.SignPairProof(key, r.id.HostID(), secret, pub),
		})
	}

	// Closed window: nothing redeems.
	if _, err := r.host.Pair(context.Background(), pairReq("anything")); code(err) != connect.CodePermissionDenied {
		t.Fatalf("closed window: %v", err)
	}

	// Bad proof must not burn the window.
	secret, _ := r.pairs.Open(r.now)
	badProof := connect.NewRequest(&linkv1.PairRequest{
		ProtocolVersion: link.ProtocolVersion,
		PairingSecret:   secret,
		DevicePublicKey: pub,
		Proof:           identity.SignPairProof(key, "some-other-host", secret, pub),
	})
	if _, err := r.host.Pair(context.Background(), badProof); code(err) != connect.CodePermissionDenied {
		t.Fatalf("bad proof: %v", err)
	}
	if !r.pairs.OpenNow(r.now) {
		t.Fatal("bad proof burned the human's window")
	}

	// Honest redemption works once; the secret is then dead.
	if _, err := r.host.Pair(context.Background(), pairReq(secret)); err != nil {
		t.Fatalf("honest pair: %v", err)
	}
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	reuse := connect.NewRequest(&linkv1.PairRequest{
		ProtocolVersion: link.ProtocolVersion,
		PairingSecret:   secret,
		DevicePublicKey: pub2,
		Proof:           identity.SignPairProof(key2, r.id.HostID(), secret, pub2),
	})
	if _, err := r.host.Pair(context.Background(), reuse); code(err) != connect.CodePermissionDenied {
		t.Fatalf("burned secret reused: %v", err)
	}

	// Expired window: the secret dies with it.
	secret2, _ := r.pairs.Open(r.now)
	r.advance(pairing.TTL + time.Second)
	if _, err := r.host.Pair(context.Background(), pairReq(secret2)); code(err) != connect.CodePermissionDenied {
		t.Fatalf("expired secret: %v", err)
	}
}

// Re-pairing the SAME device key through a fresh window replaces the
// registration — live or revoked, no unpair ceremony required. The
// stranded-phone case: cached port went stale, rediscovery failed,
// and "just scan again" must be the whole repair.
func TestRepairSameKeyThroughFreshWindow(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)
	oldToken := d.token

	// Same key, fresh window: replaces, and the old session dies with
	// the old registration.
	secret, _ := r.pairs.Open(r.now)
	res, err := r.host.Pair(context.Background(), connect.NewRequest(&linkv1.PairRequest{
		ProtocolVersion:       link.ProtocolVersion,
		PairingSecret:         secret,
		DevicePublicKey:       d.pub,
		DeviceName:            "same phone, re-paired",
		RequestedCapabilities: []string{registry.CapStatusRead},
		Proof:                 identity.SignPairProof(d.key, r.id.HostID(), secret, d.pub),
	}))
	if err != nil {
		t.Fatalf("re-pair refused: %v", err)
	}
	if res.Msg.DeviceId != d.id {
		t.Fatalf("re-pair minted a different device id: %s vs %s", res.Msg.DeviceId, d.id)
	}
	stale := linkv1connect.NewLinkServiceClient(
		&http.Client{Transport: &authed{token: oldToken, base: r.ts.Client().Transport}}, r.ts.URL)
	if _, err := stale.GetStatus(context.Background(), connect.NewRequest(&linkv1.GetStatusRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("pre-re-pair session survived: %v", err)
	}
	r.authenticate(d) // fresh session under the new registration works
	got, _ := r.reg.Get(d.id)
	if got.Name != "same phone, re-paired" || len(got.Capabilities) != 1 {
		t.Fatalf("registration not replaced: %+v", got)
	}

	// And the revoked case still re-admits by the same road.
	if err := r.srv.RevokeDevice(d.id); err != nil {
		t.Fatal(err)
	}
	secret2, _ := r.pairs.Open(r.now)
	if _, err := r.host.Pair(context.Background(), connect.NewRequest(&linkv1.PairRequest{
		ProtocolVersion: link.ProtocolVersion,
		PairingSecret:   secret2,
		DevicePublicKey: d.pub,
		Proof:           identity.SignPairProof(d.key, r.id.HostID(), secret2, d.pub),
	})); err != nil {
		t.Fatalf("re-pair after revoke refused: %v", err)
	}
	r.authenticate(d)
}

// --- Permission enforcement ------------------------------------------

func TestCapabilitiesGatePerRPCAndLive(t *testing.T) {
	r := newRig(t)
	d := r.pair(registry.CapStatusRead) // reader only
	r.authenticate(d)

	if _, err := d.link.GetStatus(context.Background(), connect.NewRequest(&linkv1.GetStatusRequest{})); err != nil {
		t.Fatalf("granted read refused: %v", err)
	}
	_, err := d.link.SubmitCommand(context.Background(), connect.NewRequest(&linkv1.SubmitCommandRequest{
		Kind: linkv1.CommandKind_COMMAND_KIND_COMPACT, SessionId: "s",
	}))
	if code(err) != connect.CodePermissionDenied {
		t.Fatalf("ungranted command: %v", err)
	}

	// The registry is live: a grant added now applies to the SAME
	// session token, no re-auth.
	if err := r.reg.SetCapabilities(d.id, []string{registry.CapStatusRead, registry.CapAgentCommand}); err != nil {
		t.Fatal(err)
	}
	res, err := d.link.SubmitCommand(context.Background(), connect.NewRequest(&linkv1.SubmitCommandRequest{
		Kind: linkv1.CommandKind_COMMAND_KIND_COMPACT, SessionId: "s",
	}))
	if err != nil || res.Msg.CommandId != "compact:s" {
		t.Fatalf("granted command after live change: %+v %v", res, err)
	}
}

// --- Revocation --------------------------------------------------------

func TestRevocationKillsStreamsTokensAndChallenges(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)
	r.srv.Publish(projection.Status{Hostname: "mac"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := d.link.WatchStatus(ctx, connect.NewRequest(&linkv1.WatchStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatalf("no opening snapshot: %v", stream.Err())
	}

	if err := r.srv.RevokeDevice(d.id); err != nil {
		t.Fatal(err)
	}

	// The open stream dies with the reason named.
	for stream.Receive() {
		// drain heartbeats/frames until the error lands
	}
	if code(stream.Err()) != connect.CodePermissionDenied {
		t.Fatalf("revoked stream ended with: %v", stream.Err())
	}
	// The session token is dead.
	_, err = d.link.GetStatus(context.Background(), connect.NewRequest(&linkv1.GetStatusRequest{}))
	if code(err) != connect.CodeUnauthenticated && code(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked token still works: %v", err)
	}
	// A fresh challenge is refused.
	_, err = r.host.Challenge(context.Background(), connect.NewRequest(&linkv1.ChallengeRequest{DeviceId: d.id}))
	if code(err) != connect.CodePermissionDenied {
		t.Fatalf("revoked challenge: %v", err)
	}
}

// --- Reconnect: resubscribe gets the latest, no gap replay ------------

func TestReconnectResumesAtLatest(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)

	r.srv.Publish(projection.Status{Hostname: "v1"})

	ctx1, cancel1 := context.WithCancel(context.Background())
	s1, err := d.link.WatchStatus(ctx1, connect.NewRequest(&linkv1.WatchStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Receive() || s1.Msg().Status.Hostname != "v1" || s1.Msg().Seq != 1 {
		t.Fatalf("first subscription opening frame: %+v %v", s1.Msg(), s1.Err())
	}
	cancel1()

	// Published while nobody watched — must not be replayed one by one.
	r.srv.Publish(projection.Status{Hostname: "v2"})
	r.srv.Publish(projection.Status{Hostname: "v3"})

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	s2, err := d.link.WatchStatus(ctx2, connect.NewRequest(&linkv1.WatchStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Receive() {
		t.Fatalf("no opening snapshot on reconnect: %v", s2.Err())
	}
	if s2.Msg().Status.Hostname != "v3" || s2.Msg().Seq != 3 {
		t.Fatalf("reconnect frame = %q seq %d, want v3 seq 3", s2.Msg().Status.Hostname, s2.Msg().Seq)
	}
}

// --- Natural-key parity: the dual-rail dedupe contract ----------------

func TestCommandIDsMatchTheCloudRail(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)

	cases := []struct {
		kind      linkv1.CommandKind
		sessionID string
		workspace string
		prompt    string
		wantKind  string
	}{
		{linkv1.CommandKind_COMMAND_KIND_COMPACT, "sess-9", "", "", "compact"},
		{linkv1.CommandKind_COMMAND_KIND_RESUME, "sess-9", "", "", "resume"},
		{linkv1.CommandKind_COMMAND_KIND_SPAWN, "", "rook", "fix the tests", "spawn"},
	}
	for _, c := range cases {
		want, err := projection.ValidCommand(c.wantKind, c.sessionID, c.workspace, c.prompt)
		if err != nil {
			t.Fatal(err)
		}
		res, err := d.link.SubmitCommand(context.Background(), connect.NewRequest(&linkv1.SubmitCommandRequest{
			Kind: c.kind, SessionId: c.sessionID, Workspace: c.workspace, Prompt: c.prompt,
		}))
		if err != nil {
			t.Fatalf("%s: %v", c.wantKind, err)
		}
		if res.Msg.CommandId != want.ID {
			t.Fatalf("%s: link minted %q, cloud rail mints %q — dual-rail dedupe broken",
				c.wantKind, res.Msg.CommandId, want.ID)
		}
	}

	// And the allowlist holds: no kind, no service.
	_, err := d.link.SubmitCommand(context.Background(), connect.NewRequest(&linkv1.SubmitCommandRequest{
		SessionId: "sess-9",
	}))
	if code(err) != connect.CodeInvalidArgument {
		t.Fatalf("kindless command: %v", err)
	}
}

// --- Pane streaming: capability gate, source edges, revocation ---------

// waitFor polls until cond holds or the deadline passes — the bridge
// between a client call returning and the server's stream goroutine
// actually reaching the hub.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestGetDigestRequiresSessionRead(t *testing.T) {
	r := newRig(t)
	r.digests["sess-1"] = projection.Digest{ID: "d1", SessionID: "sess-1", Headline: "did a thing"}
	d := r.pair(registry.CapStatusRead) // reader, but not of session content
	r.authenticate(d)

	_, err := d.link.GetDigest(context.Background(), connect.NewRequest(&linkv1.GetDigestRequest{SessionId: "sess-1"}))
	if code(err) != connect.CodePermissionDenied {
		t.Fatalf("digest without session.read: %v", err)
	}
}

func TestGetDigestServesTheFullArtifact(t *testing.T) {
	r := newRig(t)
	r.digests["sess-1"] = projection.Digest{
		ID:         "d1",
		SessionID:  "sess-1",
		Headline:   "shipped the thing",
		Bullets:    []string{"one", "two"},
		FullText:   "the complete reply, every word of it",
		Prompt:     "please ship the thing",
		Reply:      "looks good, ship it",
		ReplyState: "ready",
		Model:      "test-model",
		CostUSD:    0.0042,
		At:         time.Now().Truncate(time.Second),
	}
	d := r.pair()
	r.authenticate(d)

	got, err := d.link.GetDigest(context.Background(), connect.NewRequest(&linkv1.GetDigestRequest{SessionId: "sess-1"}))
	if err != nil {
		t.Fatal(err)
	}
	dig := got.Msg.Digest
	if dig.FullText != "the complete reply, every word of it" ||
		dig.Headline != "shipped the thing" || len(dig.Bullets) != 2 ||
		dig.Prompt != "please ship the thing" || dig.Reply != "looks good, ship it" ||
		dig.ReplyState != "ready" {
		t.Fatalf("digest came back wrong: %+v", dig)
	}

	// A session with no digest is NotFound, not an empty artifact — the
	// surface renders "nothing yet", never a blank page it must diagnose.
	_, err = d.link.GetDigest(context.Background(), connect.NewRequest(&linkv1.GetDigestRequest{SessionId: "sess-none"}))
	if code(err) != connect.CodeNotFound {
		t.Fatalf("missing digest: %v", err)
	}
	_, err = d.link.GetDigest(context.Background(), connect.NewRequest(&linkv1.GetDigestRequest{}))
	if code(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty session id: %v", err)
	}
}

func TestPaneStreamRequiresSessionRead(t *testing.T) {
	r := newRig(t)
	d := r.pair(registry.CapStatusRead) // reader, but not of panes
	r.authenticate(d)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := d.link.WatchPane(ctx, connect.NewRequest(&linkv1.WatchPaneRequest{SessionId: "sess-1"}))
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if code(err) != connect.CodePermissionDenied {
		t.Fatalf("pane stream without session.read: %v", err)
	}
	if opens, _ := r.panes.counts("sess-1"); opens != 0 {
		t.Fatal("an unauthorized watch reached the pane source")
	}
}

func TestPaneStreamFramesAndSourceEdges(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := d.link.WatchPane(ctx, connect.NewRequest(&linkv1.WatchPaneRequest{SessionId: "sess-1"}))
	if err != nil {
		t.Fatal(err)
	}
	// First watcher opens the source.
	waitFor(t, "source open", func() bool { opens, _ := r.panes.counts("sess-1"); return opens == 1 })

	r.srv.PublishPane("sess-1", projection.PaneFrame{
		Cols: 4, Rows: 1, CursorX: 2, CursorVisible: true,
		Lines: []projection.PaneRow{{
			Text: "hi",
			Runs: []projection.StyleRun{{Start: 0, Len: 2, FG: 0xFFFFFF, BG: 0x102030, Attrs: 1}},
		}},
	})

	var got *linkv1.WatchPaneResponse
	for stream.Receive() {
		if stream.Msg().Kind == linkv1.WatchPaneResponse_KIND_SNAPSHOT {
			got = stream.Msg()
			break
		}
	}
	if got == nil {
		t.Fatalf("stream ended before a frame: %v", stream.Err())
	}
	if got.Seq != 1 || got.Frame.Cols != 4 || got.Frame.CursorX != 2 || !got.Frame.CursorVisible {
		t.Fatalf("frame mangled: %+v", got.Frame)
	}
	if row := got.Frame.Lines[0]; row.Text != "hi" ||
		row.Runs[0].Fg != 0xFFFFFF || row.Runs[0].Bg != 0x102030 || row.Runs[0].Attrs != 1 {
		t.Fatalf("row mangled: %+v", row)
	}

	// Last watcher closes the source.
	cancel()
	waitFor(t, "source close", func() bool { _, closes := r.panes.counts("sess-1"); return closes == 1 })
}

func TestRevocationKillsPaneStream(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := d.link.WatchPane(ctx, connect.NewRequest(&linkv1.WatchPaneRequest{SessionId: "sess-1"}))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "source open", func() bool { opens, _ := r.panes.counts("sess-1"); return opens == 1 })

	if err := r.srv.RevokeDevice(d.id); err != nil {
		t.Fatal(err)
	}
	for stream.Receive() {
		// drain heartbeats until the error lands
	}
	if code(stream.Err()) != connect.CodePermissionDenied {
		t.Fatalf("revoked pane stream ended with: %v", stream.Err())
	}
	// The revoked watcher was the last one: the source is closed.
	waitFor(t, "source close", func() bool { _, closes := r.panes.counts("sess-1"); return closes == 1 })
}

func TestRepairDropsPaneStreams(t *testing.T) {
	r := newRig(t)
	d := r.pair()
	r.authenticate(d)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := d.link.WatchPane(ctx, connect.NewRequest(&linkv1.WatchPaneRequest{SessionId: "sess-1"}))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "source open", func() bool { opens, _ := r.panes.counts("sess-1"); return opens == 1 })

	// Re-pair the same key through a fresh window: streams minted under
	// the old registration end with it.
	secret, _ := r.pairs.Open(r.now)
	if _, err := r.host.Pair(context.Background(), connect.NewRequest(&linkv1.PairRequest{
		ProtocolVersion: link.ProtocolVersion,
		PairingSecret:   secret,
		DevicePublicKey: d.pub,
		Proof:           identity.SignPairProof(d.key, r.id.HostID(), secret, d.pub),
	})); err != nil {
		t.Fatalf("re-pair: %v", err)
	}
	for stream.Receive() {
	}
	if code(stream.Err()) != connect.CodePermissionDenied {
		t.Fatalf("pre-re-pair pane stream survived: %v", stream.Err())
	}
	waitFor(t, "source close", func() bool { _, closes := r.panes.counts("sess-1"); return closes == 1 })
}

// --- Challenge/nonce security ------------------------------------------

func TestNonceSingleUseExpiryAndBinding(t *testing.T) {
	r := newRig(t)
	a := r.pair()
	b := r.pair()

	auth := func(d *device, nonce []byte, sig []byte) error {
		_, err := r.host.Authenticate(context.Background(), connect.NewRequest(&linkv1.AuthenticateRequest{
			ProtocolVersion: link.ProtocolVersion,
			DeviceId:        d.id,
			Nonce:           nonce,
			Signature:       sig,
		}))
		return err
	}

	// Wrong key: burned, and the same nonce is dead afterwards.
	ch, _ := r.host.Challenge(context.Background(), connect.NewRequest(&linkv1.ChallengeRequest{DeviceId: a.id}))
	wrong := identity.SignAuth(b.key, r.id.HostID(), a.id, ch.Msg.Nonce)
	if err := auth(a, ch.Msg.Nonce, wrong); code(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong-key auth: %v", err)
	}
	right := identity.SignAuth(a.key, r.id.HostID(), a.id, ch.Msg.Nonce)
	if err := auth(a, ch.Msg.Nonce, right); code(err) != connect.CodePermissionDenied {
		t.Fatal("nonce survived a failed authentication")
	}

	// Cross-device: a nonce minted for A is not spendable as B.
	ch2, _ := r.host.Challenge(context.Background(), connect.NewRequest(&linkv1.ChallengeRequest{DeviceId: a.id}))
	sigB := identity.SignAuth(b.key, r.id.HostID(), b.id, ch2.Msg.Nonce)
	if err := auth(b, ch2.Msg.Nonce, sigB); code(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-device nonce: %v", err)
	}

	// Expiry.
	ch3, _ := r.host.Challenge(context.Background(), connect.NewRequest(&linkv1.ChallengeRequest{DeviceId: a.id}))
	r.advance(2 * time.Minute)
	sig3 := identity.SignAuth(a.key, r.id.HostID(), a.id, ch3.Msg.Nonce)
	if err := auth(a, ch3.Msg.Nonce, sig3); code(err) != connect.CodePermissionDenied {
		t.Fatalf("expired nonce: %v", err)
	}

	// And the honest path still works.
	r.authenticate(a)
}
