package edgeclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/anypb"

	edgev1 "github.com/incantery/rook-host/gen/rook/edge/v1"
	"github.com/incantery/rook-host/gen/rook/edge/v1/edgev1connect"
	"github.com/incantery/rook-host/edge"
	"github.com/incantery/rook-host/edgesign"
)

const testToken = "mac_test.s3cret"

// fakeEdge is an in-memory EdgeService: enough of the cloud's contract
// to exercise the client's loop without a database. Commands resolve
// when a result event lands; the ack cursor advances contiguously;
// commands named in `poison` reject their result events.
type fakeEdge struct {
	mu         sync.Mutex
	registered bool
	pending    []*edgev1.EdgeCommand
	acked      map[string]int
	poison     map[string]bool
	seqs       map[uint64]bool
	cursor     uint64
	results    []*edgev1.CommandResult
	signKey    ed25519.PrivateKey                 // set = the fake signs its envelopes
	devKey     ed25519.PublicKey                  // learned at registration
	badSig     map[string]bool                    // events that failed verification, by command
	wakes      chan edgev1.WatchEdgeResponse_Kind // nil = WatchEdge unimplemented
	poll       uint32                             // advertised poll interval
	syncs      int                                // SyncEdge calls, ever
}

func newFakeEdge() *fakeEdge {
	return &fakeEdge{acked: map[string]int{}, poison: map[string]bool{},
		seqs: map[uint64]bool{}, badSig: map[string]bool{}, poll: 1}
}

func (f *fakeEdge) RegisterDevice(_ context.Context, req *connect.Request[edgev1.RegisterDeviceRequest]) (*connect.Response[edgev1.RegisterDeviceResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered = true
	f.devKey = ed25519.PublicKey(req.Msg.PublicKey)
	res := &edgev1.RegisterDeviceResponse{DeviceId: "dev_fake", PollIntervalSeconds: f.poll}
	if f.signKey != nil {
		res.CloudPublicKey = f.signKey.Public().(ed25519.PublicKey)
	}
	return connect.NewResponse(res), nil
}

func (f *fakeEdge) SyncEdge(_ context.Context, req *connect.Request[edgev1.SyncEdgeRequest]) (*connect.Response[edgev1.SyncEdgeResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.registered {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("not registered"))
	}
	f.syncs++
	return connect.NewResponse(&edgev1.SyncEdgeResponse{
		Commands:            slices.Clone(f.pending),
		AckedDeviceSequence: f.cursor,
		PollIntervalSeconds: f.poll,
	}), nil
}

func (f *fakeEdge) AckCommand(_ context.Context, req *connect.Request[edgev1.AckCommandRequest]) (*connect.Response[edgev1.AckCommandResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked[req.Msg.CommandId]++
	return connect.NewResponse(&edgev1.AckCommandResponse{}), nil
}

func (f *fakeEdge) SubmitEvents(_ context.Context, req *connect.Request[edgev1.SubmitEventsRequest]) (*connect.Response[edgev1.SubmitEventsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var rejections []*edgev1.EventRejection
	for _, ev := range req.Msg.Events {
		if f.poison[ev.CommandId] {
			rejections = append(rejections, &edgev1.EventRejection{
				DeviceSequence: ev.DeviceSequence, Reason: "poisoned command",
			})
			continue
		}
		if len(f.devKey) > 0 && !edgesign.VerifyEvent(f.devKey, ev) {
			f.badSig[ev.CommandId] = true
			rejections = append(rejections, &edgev1.EventRejection{
				DeviceSequence: ev.DeviceSequence, Reason: "device_signature does not verify",
			})
			continue
		}
		var res edgev1.CommandResult
		if err := ev.Payload.UnmarshalTo(&res); err != nil {
			rejections = append(rejections, &edgev1.EventRejection{
				DeviceSequence: ev.DeviceSequence, Reason: "not a CommandResult",
			})
			continue
		}
		f.results = append(f.results, &res)
		f.pending = deleteCommand(f.pending, ev.CommandId)
		f.seqs[ev.DeviceSequence] = true
	}
	for f.seqs[f.cursor+1] {
		f.cursor++
	}
	return connect.NewResponse(&edgev1.SubmitEventsResponse{
		AckedDeviceSequence: f.cursor, Rejections: rejections,
	}), nil
}

func (f *fakeEdge) RenewLeases(context.Context, *connect.Request[edgev1.RenewLeasesRequest]) (*connect.Response[edgev1.RenewLeasesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("not in the fake"))
}

// WatchEdge streams whatever kinds the test feeds through f.wakes,
// after the LISTENING greeting the real gateway sends. A fake without
// the channel answers Unimplemented — the degradation path is part of
// the contract under test.
func (f *fakeEdge) WatchEdge(ctx context.Context, _ *connect.Request[edgev1.WatchEdgeRequest], stream *connect.ServerStream[edgev1.WatchEdgeResponse]) error {
	if f.wakes == nil {
		return connect.NewError(connect.CodeUnimplemented, fmt.Errorf("no wakes in this fake"))
	}
	if err := stream.Send(&edgev1.WatchEdgeResponse{Kind: edgev1.WatchEdgeResponse_KIND_LISTENING}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case kind := <-f.wakes:
			if err := stream.Send(&edgev1.WatchEdgeResponse{Kind: kind}); err != nil {
				return err
			}
		}
	}
}

func (f *fakeEdge) ResolveArtifactUpload(context.Context, *connect.Request[edgev1.ResolveArtifactUploadRequest]) (*connect.Response[edgev1.ResolveArtifactUploadResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("not in the fake"))
}

func deleteCommand(cmds []*edgev1.EdgeCommand, id string) []*edgev1.EdgeCommand {
	out := cmds[:0]
	for _, c := range cmds {
		if c.CommandId != id {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeEdge) addCommand(id string) *edgev1.EdgeCommand {
	payload, _ := anypb.New(&edgev1.CreateWorktree{TaskId: "task_t", WorkflowRunId: "wfr_t"})
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := &edgev1.EdgeCommand{
		ProtocolVersion: edge.ProtocolVersion,
		CommandId:       id,
		DeviceId:        "dev_fake",
		WorkflowRunId:   "wfr_t",
		Payload:         payload,
	}
	if f.signKey != nil {
		edgesign.SignCommand(f.signKey, cmd)
	}
	f.pending = append(f.pending, cmd)
	return cmd
}

// serve mounts the fake behind real HTTP with the production auth
// shape: a bearer token checked BEFORE the handler, wrong or missing
// answered with a bare 401 — exactly what api.rookide.com does.
func serve(t *testing.T, f *fakeEdge) string {
	t.Helper()
	path, handler := edgev1connect.NewEdgeServiceHandler(f)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func succeedAll(_ context.Context, cmd *edgev1.EdgeCommand) (string, []byte) {
	return "succeeded", fmt.Appendf(nil, `{"did":%q}`, cmd.CommandId)
}

// The wrong token — and no token — must die at the gate, and the gate's
// bare 401 must surface as CodeUnauthenticated, not a parse error.
func TestBearerGate(t *testing.T) {
	url := serve(t, newFakeEdge())
	ctx := context.Background()

	bad := &Client{RPC: NewRPC(http.DefaultClient, url, "mac_test.wrong"), Execute: succeedAll}
	if _, err := bad.Register(ctx, "box", "test", nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong token: %v, want unauthenticated", err)
	}
	anon := &Client{RPC: edgev1connect.NewEdgeServiceClient(http.DefaultClient, url), Execute: succeedAll}
	if _, err := anon.Register(ctx, "box", "test", nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no token: %v, want unauthenticated", err)
	}

	good := &Client{RPC: NewRPC(http.DefaultClient, url, testToken), Execute: succeedAll}
	dev, err := good.Register(ctx, "box", "test", []string{"worktree"})
	if err != nil || dev != "dev_fake" {
		t.Fatalf("register: (%q, %v)", dev, err)
	}
}

// One full pass: two pending commands become two acks, two executions,
// two result events with sequences continuing from the server cursor —
// and a second pass finds nothing left to do.
func TestSyncOncePass(t *testing.T) {
	fake := newFakeEdge()
	fake.addCommand("cmd_a")
	fake.addCommand("cmd_b")
	url := serve(t, fake)
	ctx := context.Background()

	var executed []string
	c := &Client{
		RPC: NewRPC(http.DefaultClient, url, testToken),
		Execute: func(ctx context.Context, cmd *edgev1.EdgeCommand) (string, []byte) {
			var payload edgev1.CreateWorktree
			if err := cmd.Payload.UnmarshalTo(&payload); err != nil {
				t.Errorf("payload of %s: %v", cmd.CommandId, err)
			}
			executed = append(executed, cmd.CommandId)
			return "succeeded", []byte(`{"ok":true}`)
		},
	}
	if _, err := c.Register(ctx, "box", "test", nil); err != nil {
		t.Fatalf("register: %v", err)
	}

	report, err := c.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if report.Commands != 2 || report.Reported != 2 || report.AckedSeq != 2 || len(report.Rejections) != 0 {
		t.Fatalf("report: %+v", report)
	}
	if len(executed) != 2 {
		t.Fatalf("executed: %v", executed)
	}
	if fake.acked["cmd_a"] == 0 || fake.acked["cmd_b"] == 0 {
		t.Fatalf("acks must precede execution: %v", fake.acked)
	}
	for _, res := range fake.results {
		if res.Status != "succeeded" || res.CommandId == "" {
			t.Fatalf("result: %+v", res)
		}
	}

	again, err := c.SyncOnce(ctx)
	if err != nil || again.Commands != 0 || again.Reported != 0 || again.AckedSeq != 2 {
		t.Fatalf("resolved commands must stop arriving: (%+v, %v)", again, err)
	}
}

// The signed loop: the client verifies what it receives, rejects what
// does not verify WITHOUT executing it, and signs what it submits.
func TestSignedLoop(t *testing.T) {
	fake := newFakeEdge()
	_, cloudPriv, err := edgesign.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fake.signKey = cloudPriv
	good := fake.addCommand("cmd_good")
	_ = good
	tampered := fake.addCommand("cmd_tampered")
	tampered.FencingToken = 99 // after signing: the signature is now a lie
	url := serve(t, fake)
	ctx := context.Background()

	_, devKey, err := edgesign.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var executed []string
	c := &Client{
		RPC: NewRPC(http.DefaultClient, url, testToken),
		Key: devKey,
		Execute: func(_ context.Context, cmd *edgev1.EdgeCommand) (string, []byte) {
			executed = append(executed, cmd.CommandId)
			return "succeeded", []byte(`{"ok":true}`)
		},
	}
	if _, err := c.Register(ctx, "box", "test", nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !c.CloudSigning() {
		t.Fatal("client must learn the cloud key at registration")
	}

	report, err := c.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// The tampered command was never executed — it was resolved as
	// rejected instead, and both results carried verifying signatures.
	if len(executed) != 1 || executed[0] != "cmd_good" {
		t.Fatalf("executed: %v, want only cmd_good", executed)
	}
	if report.Reported != 2 || len(report.Rejections) != 0 {
		t.Fatalf("report: %+v (badSig: %v)", report, fake.badSig)
	}
	statuses := map[string]string{}
	for _, res := range fake.results {
		statuses[res.CommandId] = res.Status
	}
	if statuses["cmd_good"] != "succeeded" || statuses["cmd_tampered"] != "rejected" {
		t.Fatalf("results: %v", statuses)
	}
}

// The device's §12.2 half: a command spending a grant executes only
// when the whole checklist holds — a verified ledger payload and a
// grant whose signature, scope, and digest binding all check out. A
// broken binding is a rejection, not a warning, and never an effect.
func TestGrantChecklistGuardsExecution(t *testing.T) {
	fake := newFakeEdge()
	_, cloudPriv, err := edgesign.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fake.signKey = cloudPriv

	// A granted command, wired the way envelope() wires it: ledger
	// payload aboard, digest over those bytes, grant bound to them.
	granted := func(id string, breakIt func(*edgev1.EdgeCommand, *edgesign.GrantDoc)) {
		ledger := []byte(`{"op":"cleanup_worktree","step":"cleanup"}`)
		sum := sha256.Sum256(ledger)
		payload, _ := anypb.New(&edgev1.CleanupWorktree{WorktreeId: "worktree_wfr_t"})
		cmd := &edgev1.EdgeCommand{
			ProtocolVersion: edge.ProtocolVersion, CommandId: id,
			DeviceId: "dev_fake", WorkflowRunId: "wfr_t",
			ResourceType: "worktree", ResourceId: "worktree_wfr_t",
			ApprovalGrantId: "apr_" + id,
			Payload:         payload, PayloadDigest: sum[:], LedgerPayload: ledger,
		}
		doc := edgesign.GrantDoc{
			Schema: edgesign.GrantSchema, GrantID: "apr_" + id, RequestID: "apr_" + id,
			ActorID: "usr_t", ActionType: "cleanup_worktree",
			ActionDigest: "sha256:" + edgesign.ActionDigest(
				cmd.WorkflowRunId, cmd.DeviceId, cmd.ResourceType, cmd.ResourceId, ledger),
			ResourceScope: []string{"device:dev_fake", "worktree:worktree_wfr_t"},
			WorkflowRunID: "wfr_t",
			IssuedAt:      time.Now().UTC().Format(time.RFC3339),
			ExpiresAt:     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			SingleUse:     true,
		}
		if breakIt != nil {
			breakIt(cmd, &doc)
		}
		if err := edgesign.SignGrant(cloudPriv, &doc); err != nil {
			t.Fatal(err)
		}
		cmd.ApprovalGrant, _ = json.Marshal(doc)
		edgesign.SignCommand(cloudPriv, cmd)
		fake.mu.Lock()
		fake.pending = append(fake.pending, cmd)
		fake.mu.Unlock()
	}
	granted("cmd_clean", nil)
	// The grant's digest names a DIFFERENT action than the command
	// carries — the exact mutation the binding exists to catch. Signed
	// and signature-valid all the way down, refused anyway.
	granted("cmd_bound_elsewhere", func(cmd *edgev1.EdgeCommand, doc *edgesign.GrantDoc) {
		doc.ActionDigest = "sha256:" + edgesign.ActionDigest(
			cmd.WorkflowRunId, cmd.DeviceId, cmd.ResourceType, cmd.ResourceId,
			[]byte(`{"op":"cleanup_worktree","step":"cleanup","force":"true"}`))
	})

	url := serve(t, fake)
	ctx := context.Background()
	var executed []string
	c := &Client{
		RPC: NewRPC(http.DefaultClient, url, testToken),
		Execute: func(_ context.Context, cmd *edgev1.EdgeCommand) (string, []byte) {
			executed = append(executed, cmd.CommandId)
			return "succeeded", []byte(`{"ok":true}`)
		},
	}
	if _, err := c.Register(ctx, "box", "test", nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.SyncOnce(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(executed) != 1 || executed[0] != "cmd_clean" {
		t.Fatalf("executed: %v, want only cmd_clean", executed)
	}
	statuses := map[string]string{}
	for _, res := range fake.results {
		statuses[res.CommandId] = res.Status
	}
	if statuses["cmd_clean"] != "succeeded" || statuses["cmd_bound_elsewhere"] != "rejected" {
		t.Fatalf("results: %v", statuses)
	}
}

// A rejected event surfaces in the report and does not block the good
// one riding in the same batch.
func TestRejectionsSurface(t *testing.T) {
	fake := newFakeEdge()
	fake.addCommand("cmd_good")
	fake.addCommand("cmd_bad")
	fake.poison["cmd_bad"] = true
	url := serve(t, fake)
	ctx := context.Background()

	c := &Client{RPC: NewRPC(http.DefaultClient, url, testToken), Execute: succeedAll}
	if _, err := c.Register(ctx, "box", "test", nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	report, err := c.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(report.Rejections) != 1 {
		t.Fatalf("rejections: %v", report.Rejections)
	}
	if len(fake.results) != 1 || fake.results[0].CommandId != "cmd_good" {
		t.Fatalf("good event must land: %+v", fake.results)
	}
}

// awaitResult polls the fake until a result for cmdID lands or the
// deadline passes. The deadline IS the assertion in the wake tests: a
// poll interval of an hour means only the stream can explain success.
func awaitResult(t *testing.T, f *fakeEdge, cmdID string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		for _, r := range f.results {
			if r.CommandId == cmdID {
				f.mu.Unlock()
				return
			}
		}
		f.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("result for %s never arrived", cmdID)
}

// The accelerator accelerating: with an hour-long poll interval, a
// command minted mid-wait is executed within seconds because the wake
// stream said "sync now" — and heartbeats say nothing at all.
func TestFollowWakesEarly(t *testing.T) {
	fake := newFakeEdge()
	fake.poll = 3600
	fake.wakes = make(chan edgev1.WatchEdgeResponse_Kind, 4)
	url := serve(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Client{RPC: NewRPC(http.DefaultClient, url, testToken), Execute: succeedAll}
	if _, err := c.Register(ctx, "box", "test", nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Follow(ctx) }()

	// The first (empty) pass must land BEFORE the mint, or the test
	// passes by racing the initial sync instead of proving the wake.
	deadline := time.Now().Add(5 * time.Second)
	for {
		fake.mu.Lock()
		n := fake.syncs
		fake.mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first sync pass never happened")
		}
		time.Sleep(10 * time.Millisecond)
	}

	fake.addCommand("cmd_woken")
	fake.wakes <- edgev1.WatchEdgeResponse_KIND_WAKE
	awaitResult(t, fake, "cmd_woken", 5*time.Second)

	// Heartbeats keep the line open and trigger nothing.
	fake.mu.Lock()
	syncsBefore := fake.syncs
	fake.mu.Unlock()
	fake.wakes <- edgev1.WatchEdgeResponse_KIND_HEARTBEAT
	fake.wakes <- edgev1.WatchEdgeResponse_KIND_HEARTBEAT
	time.Sleep(300 * time.Millisecond)
	fake.mu.Lock()
	syncsAfter := fake.syncs
	fake.mu.Unlock()
	if syncsAfter != syncsBefore {
		t.Fatalf("heartbeats caused %d extra syncs", syncsAfter-syncsBefore)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("follow end: %v", err)
	}
}

// A cloud without the wake stream: the watcher retires on Unimplemented
// and the poll loop, never having known, carries the whole load.
func TestWatchAbsenceFallsBackToPolling(t *testing.T) {
	fake := newFakeEdge() // wakes nil = WatchEdge unimplemented; poll 1s
	url := serve(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Client{RPC: NewRPC(http.DefaultClient, url, testToken), Execute: succeedAll}
	if _, err := c.Register(ctx, "box", "test", nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Follow(ctx) }()

	fake.addCommand("cmd_polled")
	awaitResult(t, fake, "cmd_polled", 5*time.Second)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("follow end: %v", err)
	}
}
