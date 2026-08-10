package link

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/incantery/rook-host/projection"
)

// Round-trip property: any clamped projection survives the wire shape
// unchanged. Randomized because the failure mode is a forgotten field
// in one of the two converters, and a fixed fixture only guards the
// fields its author remembered.
func TestStatusProtoRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		s := randomStatus(rng)
		s.Clamp()
		got := statusFromProto(statusToProto(s, time.Time{}))
		if !reflect.DeepEqual(s, got) {
			t.Fatalf("round trip diverged (case %d):\n in: %+v\nout: %+v", i, s, got)
		}
	}
}

var states = []string{"working", "needs_input", "quiet"}

func randomStatus(rng *rand.Rand) projection.Status {
	s := projection.Status{
		Hostname:    randStr(rng, 12),
		RookVersion: randStr(rng, 8),
		HostID:      randStr(rng, 26),
	}
	for w := 0; w < rng.Intn(4); w++ {
		ws := projection.Workspace{
			Name:      randStr(rng, 10),
			Branch:    randStr(rng, 10),
			Attention: rng.Intn(5),
		}
		for a := 0; a < rng.Intn(4); a++ {
			ag := projection.Agent{
				ID:      randStr(rng, 16),
				State:   states[rng.Intn(len(states))],
				Title:   randStr(rng, 30),
				Model:   randStr(rng, 10),
				CostUSD: float64(rng.Intn(10000)) / 100,
				CtxPct:  rng.Intn(150),
			}
			if rng.Intn(2) == 0 {
				ag.Ask = randStr(rng, 60)
				ag.AskID = randStr(rng, 20)
			}
			if rng.Intn(2) == 0 {
				d := &projection.AgentDigest{Headline: randStr(rng, 50)}
				for b := 0; b < rng.Intn(3); b++ {
					d.Bullets = append(d.Bullets, randStr(rng, 40))
				}
				ag.Digest = d
			}
			if rng.Intn(2) == 0 {
				ag.LastEvent = time.Unix(rng.Int63n(2_000_000_000), 0).UTC()
			}
			ws.Agents = append(ws.Agents, ag)
		}
		s.Workspaces = append(s.Workspaces, ws)
	}
	return s
}

func randStr(rng *rand.Rand, max int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz éñ中"
	n := rng.Intn(max + 1)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[rng.Intn(26)]) // ascii core
	}
	if n > 3 && rng.Intn(3) == 0 {
		b.WriteString("é中") // exercise multi-byte survival
	}
	return b.String()
}

// Same property for pane frames: any clamped frame survives the wire
// shape unchanged.
func TestPaneFrameProtoRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(43))
	for i := 0; i < 200; i++ {
		f := randomPaneFrame(rng)
		f.Clamp()
		got := paneFromProto(paneToProto(f))
		if !reflect.DeepEqual(f, got) {
			t.Fatalf("pane round trip diverged (case %d):\n in: %+v\nout: %+v", i, f, got)
		}
	}
}

func randomPaneFrame(rng *rand.Rand) projection.PaneFrame {
	f := projection.PaneFrame{
		Cols:          rng.Intn(200),
		Rows:          rng.Intn(60),
		CursorX:       rng.Intn(200),
		CursorY:       rng.Intn(60),
		CursorVisible: rng.Intn(2) == 0,
	}
	for r := 0; r < rng.Intn(5); r++ {
		row := projection.PaneRow{Text: randStr(rng, 80)}
		for s := 0; s < rng.Intn(4); s++ {
			row.Runs = append(row.Runs, projection.StyleRun{
				Start: rng.Uint32() % 200,
				Len:   rng.Uint32() % 200,
				FG:    rng.Uint32() % 0x1000000,
				BG:    rng.Uint32() % 0x1000000,
				Attrs: rng.Uint32() % 32,
			})
		}
		f.Lines = append(f.Lines, row)
	}
	return f
}

// Unknown agent states cross the wire as UNSPECIFIED, never invented.
func TestUnknownStateBecomesUnspecified(t *testing.T) {
	s := projection.Status{Workspaces: []projection.Workspace{{
		Name:   "w",
		Agents: []projection.Agent{{State: "meditating"}},
	}}}
	got := statusFromProto(statusToProto(s, time.Time{}))
	if got.Workspaces[0].Agents[0].State != "" {
		t.Fatalf("invented a state: %q", got.Workspaces[0].Agents[0].State)
	}
}
