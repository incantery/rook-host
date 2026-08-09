package edgesign

// The cross-repo drift tripwire. The rook IDE repo reimplements this
// package against its own generated bindings (its choice: no module
// coupling), which leaves two hand-kept copies of security-critical
// canonical encodings. testdata/golden.json is the treaty between them:
// fixed inputs and the exact canonical bytes, signatures, and digests
// they must produce. The IDE repo carries a byte-identical copy of the
// file and asserts the same vectors against its implementation — drift
// on either side fails that side's tests before it fails in the field.
//
// Regenerate with `go test ./internal/edgesign -run Golden -update`
// after any DELIBERATE encoding change (which is a protocol change and
// a new domain label), then re-copy the file to the IDE repo.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	edgev1 "github.com/incantery/rook-host/gen/rook/edge/v1"
)

var update = flag.Bool("update", false, "rewrite testdata/golden.json from the current implementation")

// goldenFile mirrors the JSON layout. Every byte field is hex; seeds
// and grant signatures are base64 because that is their wire form.
type goldenFile struct {
	CloudSeed  string `json:"cloudSeed"`
	DeviceSeed string `json:"deviceSeed"`
	Command    struct {
		ProtocolVersion          string `json:"protocolVersion"`
		CommandID                string `json:"commandId"`
		LogicalOperationID       string `json:"logicalOperationId"`
		Attempt                  uint32 `json:"attempt"`
		DeviceID                 string `json:"deviceId"`
		TaskID                   string `json:"taskId"`
		WorkflowRunID            string `json:"workflowRunId"`
		ResourceType             string `json:"resourceType"`
		ResourceID               string `json:"resourceId"`
		FencingToken             uint64 `json:"fencingToken"`
		ExpectedAggregateVersion uint64 `json:"expectedAggregateVersion"`
		ExpiresAt                string `json:"expiresAt"` // RFC3339
		IdempotencyKey           string `json:"idempotencyKey"`
		ApprovalGrantID          string `json:"approvalGrantId"`
		PolicyContextHash        string `json:"policyContextHash"`
		PayloadType              string `json:"payloadType"`
		PayloadValueHex          string `json:"payloadValueHex"`
		PayloadDigestHex         string `json:"payloadDigestHex"`
		CanonicalHex             string `json:"canonicalHex"`
		SignatureHex             string `json:"signatureHex"`
	} `json:"command"`
	Event struct {
		EventID          string `json:"eventId"`
		DeviceID         string `json:"deviceId"`
		DeviceSequence   uint64 `json:"deviceSequence"`
		CommandID        string `json:"commandId"`
		Type             string `json:"type"`
		OccurredAt       string `json:"occurredAt"` // RFC3339
		FencingToken     uint64 `json:"fencingToken"`
		PayloadType      string `json:"payloadType"`
		PayloadValueHex  string `json:"payloadValueHex"`
		PayloadDigestHex string `json:"payloadDigestHex"`
		CanonicalHex     string `json:"canonicalHex"`
		SignatureHex     string `json:"signatureHex"`
	} `json:"event"`
	Grant struct {
		Doc          GrantDoc `json:"doc"` // ServerSignature filled = the expected signature
		UnsignedJSON string   `json:"unsignedJson"`
	} `json:"grant"`
	ActionDigestVector struct {
		WorkflowRunID string `json:"workflowRunId"`
		DeviceID      string `json:"deviceId"`
		ResourceType  string `json:"resourceType"`
		ResourceID    string `json:"resourceId"`
		LedgerPayload string `json:"ledgerPayload"`
		Digest        string `json:"digest"`
	} `json:"actionDigest"`
}

const goldenPath = "testdata/golden.json"

// Deterministic keys for the vectors — test fixtures, not secrets.
func goldenKeys(t *testing.T, g *goldenFile) (cloud, device ed25519.PrivateKey) {
	t.Helper()
	if *update {
		g.CloudSeed = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
		g.DeviceSeed = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	}
	var err error
	if cloud, err = DecodeSeed(g.CloudSeed); err != nil {
		t.Fatal(err)
	}
	if device, err = DecodeSeed(g.DeviceSeed); err != nil {
		t.Fatal(err)
	}
	return cloud, device
}

func TestGoldenVectors(t *testing.T) {
	var g goldenFile
	if !*update {
		raw, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read %s (regenerate with -update): %v", goldenPath, err)
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
	}
	cloudKey, deviceKey := goldenKeys(t, &g)

	if *update {
		fillGolden(t, &g, cloudKey, deviceKey)
	}

	// Command: rebuild the envelope purely from the fixture, then the
	// canonical bytes and signature must match to the byte.
	c := &g.Command
	cmdExpires, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	cmd := &edgev1.EdgeCommand{
		ProtocolVersion: c.ProtocolVersion, CommandId: c.CommandID,
		LogicalOperationId: c.LogicalOperationID, Attempt: c.Attempt,
		DeviceId: c.DeviceID, TaskId: c.TaskID, WorkflowRunId: c.WorkflowRunID,
		ResourceType: c.ResourceType, ResourceId: c.ResourceID,
		FencingToken: c.FencingToken, ExpectedAggregateVersion: c.ExpectedAggregateVersion,
		ExpiresAt: timestamppb.New(cmdExpires), IdempotencyKey: c.IdempotencyKey,
		ApprovalGrantId: c.ApprovalGrantID, PolicyContextHash: c.PolicyContextHash,
		Payload:       &anypb.Any{TypeUrl: c.PayloadType, Value: unhex(t, c.PayloadValueHex)},
		PayloadDigest: unhex(t, c.PayloadDigestHex),
	}
	if got := hex.EncodeToString(commandBytes(cmd)); got != c.CanonicalHex {
		t.Errorf("command canonical bytes drifted:\n got %s\nwant %s", got, c.CanonicalHex)
	}
	SignCommand(cloudKey, cmd)
	if got := hex.EncodeToString(cmd.CloudSignature); got != c.SignatureHex {
		t.Errorf("command signature drifted: got %s want %s", got, c.SignatureHex)
	}

	// Event, same discipline, device key.
	e := &g.Event
	evOccurred, err := time.Parse(time.RFC3339, e.OccurredAt)
	if err != nil {
		t.Fatal(err)
	}
	ev := &edgev1.EdgeEvent{
		EventId: e.EventID, DeviceId: e.DeviceID, DeviceSequence: e.DeviceSequence,
		CommandId: e.CommandID, Type: e.Type, OccurredAt: timestamppb.New(evOccurred),
		FencingToken:  e.FencingToken,
		Payload:       &anypb.Any{TypeUrl: e.PayloadType, Value: unhex(t, e.PayloadValueHex)},
		PayloadDigest: unhex(t, e.PayloadDigestHex),
	}
	if got := hex.EncodeToString(eventBytes(ev)); got != e.CanonicalHex {
		t.Errorf("event canonical bytes drifted:\n got %s\nwant %s", got, e.CanonicalHex)
	}
	SignEvent(deviceKey, ev)
	if got := hex.EncodeToString(ev.DeviceSignature); got != e.SignatureHex {
		t.Errorf("event signature drifted: got %s want %s", got, e.SignatureHex)
	}

	// Grant: unsigned JSON and signature both pinned.
	doc := g.Grant.Doc
	wantSig := doc.ServerSignature
	if err := SignGrant(cloudKey, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ServerSignature != wantSig {
		t.Errorf("grant signature drifted: got %s want %s", doc.ServerSignature, wantSig)
	}
	unsigned := doc
	unsigned.ServerSignature = ""
	if raw, _ := json.Marshal(unsigned); string(raw) != g.Grant.UnsignedJSON {
		t.Errorf("grant canonical JSON drifted:\n got %s\nwant %s", raw, g.Grant.UnsignedJSON)
	}
	if !VerifyGrantSignature(cloudKey.Public().(ed25519.PublicKey), doc) {
		t.Error("golden grant must verify")
	}

	// The action digest formula.
	a := &g.ActionDigestVector
	if got := ActionDigest(a.WorkflowRunID, a.DeviceID, a.ResourceType, a.ResourceID, []byte(a.LedgerPayload)); got != a.Digest {
		t.Errorf("action digest drifted: got %s want %s", got, a.Digest)
	}

	if *update {
		raw, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s — copy it verbatim to the IDE repo's edgesign testdata", goldenPath)
	}
}

// fillGolden builds the fixture's inputs and expected outputs from the
// current implementation. Only -update runs it.
func fillGolden(t *testing.T, g *goldenFile, cloudKey, deviceKey ed25519.PrivateKey) {
	t.Helper()
	ledger := []byte(`{"op":"cleanup_worktree","step":"cleanup"}`)
	payload, err := anypb.New(&edgev1.CleanupWorktree{WorktreeId: "worktree_wfr_g1"})
	if err != nil {
		t.Fatal(err)
	}
	c := &g.Command
	c.ProtocolVersion, c.CommandID = "rook-edge/1", "cmd_wfr_g1_cleanup_4"
	c.LogicalOperationID, c.Attempt = "op_wfr_g1_cleanup", 1
	c.DeviceID, c.TaskID, c.WorkflowRunID = "dev_g1", "task_g1", "wfr_g1"
	c.ResourceType, c.ResourceID = "worktree", "worktree_wfr_g1"
	c.FencingToken, c.ExpectedAggregateVersion = 3, 7
	c.ExpiresAt = "2026-07-27T12:00:00Z"
	c.IdempotencyKey, c.ApprovalGrantID = "cmd_wfr_g1_cleanup_4", "apr_wfr_g1_cleanup_4"
	c.PolicyContextHash = "sha256:policy"
	c.PayloadType, c.PayloadValueHex = payload.TypeUrl, hex.EncodeToString(payload.Value)
	c.PayloadDigestHex = hex.EncodeToString(digestOf(ledger))

	expires, _ := time.Parse(time.RFC3339, c.ExpiresAt)
	cmd := &edgev1.EdgeCommand{
		ProtocolVersion: c.ProtocolVersion, CommandId: c.CommandID,
		LogicalOperationId: c.LogicalOperationID, Attempt: c.Attempt,
		DeviceId: c.DeviceID, TaskId: c.TaskID, WorkflowRunId: c.WorkflowRunID,
		ResourceType: c.ResourceType, ResourceId: c.ResourceID,
		FencingToken: c.FencingToken, ExpectedAggregateVersion: c.ExpectedAggregateVersion,
		ExpiresAt: timestamppb.New(expires), IdempotencyKey: c.IdempotencyKey,
		ApprovalGrantId: c.ApprovalGrantID, PolicyContextHash: c.PolicyContextHash,
		Payload: payload, PayloadDigest: unhex(t, c.PayloadDigestHex),
	}
	c.CanonicalHex = hex.EncodeToString(commandBytes(cmd))
	SignCommand(cloudKey, cmd)
	c.SignatureHex = hex.EncodeToString(cmd.CloudSignature)

	result, err := anypb.New(&edgev1.CommandResult{CommandId: c.CommandID, Status: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	e := &g.Event
	e.EventID, e.DeviceID, e.DeviceSequence = "devevt_cmd_wfr_g1_cleanup_4_succeeded", "dev_g1", 42
	e.CommandID, e.Type = c.CommandID, "com.rook.edge.command_result.v1"
	e.OccurredAt, e.FencingToken = "2026-07-27T11:59:00Z", 3
	e.PayloadType, e.PayloadValueHex = result.TypeUrl, hex.EncodeToString(result.Value)
	e.PayloadDigestHex = hex.EncodeToString(digestOf(result.Value))
	occurred, _ := time.Parse(time.RFC3339, e.OccurredAt)
	ev := &edgev1.EdgeEvent{
		EventId: e.EventID, DeviceId: e.DeviceID, DeviceSequence: e.DeviceSequence,
		CommandId: e.CommandID, Type: e.Type, OccurredAt: timestamppb.New(occurred),
		FencingToken: e.FencingToken, Payload: result, PayloadDigest: unhex(t, e.PayloadDigestHex),
	}
	e.CanonicalHex = hex.EncodeToString(eventBytes(ev))
	SignEvent(deviceKey, ev)
	e.SignatureHex = hex.EncodeToString(ev.DeviceSignature)

	a := &g.ActionDigestVector
	a.WorkflowRunID, a.DeviceID = "wfr_g1", "dev_g1"
	a.ResourceType, a.ResourceID = "worktree", "worktree_wfr_g1"
	a.LedgerPayload = string(ledger)
	a.Digest = ActionDigest(a.WorkflowRunID, a.DeviceID, a.ResourceType, a.ResourceID, ledger)

	doc := GrantDoc{
		Schema: GrantSchema, GrantID: "apr_wfr_g1_cleanup_4", RequestID: "apr_wfr_g1_cleanup_4",
		ActorID: "usr_g1", ActionType: "cleanup_worktree",
		ActionDigest:  "sha256:" + a.Digest,
		ResourceScope: []string{"device:dev_g1", "worktree:worktree_wfr_g1"},
		WorkflowRunID: "wfr_g1",
		IssuedAt:      "2026-07-27T11:00:00Z",
		ExpiresAt:     "2026-07-27T12:00:00Z",
		SingleUse:     true,
	}
	unsigned, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	g.Grant.UnsignedJSON = string(unsigned)
	if err := SignGrant(cloudKey, &doc); err != nil {
		t.Fatal(err)
	}
	g.Grant.Doc = doc
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
