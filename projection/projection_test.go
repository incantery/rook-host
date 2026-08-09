package projection

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClamp(t *testing.T) {
	s := &Status{
		Hostname:   strings.Repeat("h", 500),
		Workspaces: make([]Workspace, 150),
	}
	for i := range s.Workspaces {
		s.Workspaces[i] = Workspace{
			Name:   "ws",
			Agents: make([]Agent, 80),
		}
	}
	// a multi-byte rune straddling the cut must not yield invalid UTF-8
	s.Workspaces[0].Agents[0].Ask = strings.Repeat("é", 1500)

	s.Clamp()

	if len(s.Hostname) != 200 {
		t.Errorf("hostname len = %d", len(s.Hostname))
	}
	if len(s.Workspaces) != 100 {
		t.Errorf("workspaces = %d", len(s.Workspaces))
	}
	if len(s.Workspaces[0].Agents) != 50 {
		t.Errorf("agents = %d", len(s.Workspaces[0].Agents))
	}
	ask := s.Workspaces[0].Agents[0].Ask
	if len(ask) > 2000 {
		t.Errorf("ask len = %d", len(ask))
	}
	if !utf8.ValidString(ask) {
		t.Error("clip broke UTF-8")
	}
}

func TestValidAnswerBoundsBothHalves(t *testing.T) {
	if _, err := ValidAnswer("sess:abcd1234", "yes, ship it"); err != nil {
		t.Fatalf("honest answer refused: %v", err)
	}
	for name, tc := range map[string][2]string{
		"empty text":  {"sess:abcd1234", "   "},
		"empty askId": {"", "yes"},
		"askId too":   {strings.Repeat("x", MaxAskIDLen+1), "yes"},
		"text too":    {"a", strings.Repeat("y", MaxAnswerLen+1)},
	} {
		if _, err := ValidAnswer(tc[0], tc[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClampBoundsAskID(t *testing.T) {
	s := &Status{Workspaces: []Workspace{{Name: "w", Agents: []Agent{{State: "needs_input", AskID: strings.Repeat("z", 500)}}}}}
	s.Clamp()
	if got := len(s.Workspaces[0].Agents[0].AskID); got != MaxAskIDLen {
		t.Fatalf("askId after clamp: %d", got)
	}
}

// A command is taken only from the allowlist — "run this shell
// command" must never validate — and its natural id is what makes
// one-pending-per-(kind,session) a filter instead of a transaction.
func TestValidCommandAllowlistAndNaturalID(t *testing.T) {
	c, err := ValidCommand(" compact ", " sess-1 ", "", "")
	if err != nil || c.ID != "compact:sess-1" || c.Kind != "compact" || c.SessionID != "sess-1" {
		t.Fatalf("valid compact: %+v %v", c, err)
	}
	r, err := ValidCommand("resume", "sess-2", "", "")
	if err != nil || r.ID != "resume:sess-2" {
		t.Fatalf("valid resume: %+v %v", r, err)
	}
	// A spawn names a workspace and may carry a prompt; the prompt is
	// folded into the natural id so a double-tap is one spawn but a
	// different prompt is a different command.
	s1, err := ValidCommand("spawn", "", "rook", "fix the flaky test")
	if err != nil || s1.Workspace != "rook" || s1.Prompt != "fix the flaky test" {
		t.Fatalf("valid spawn: %+v %v", s1, err)
	}
	s2, _ := ValidCommand("spawn", "", "rook", "fix the flaky test")
	s3, _ := ValidCommand("spawn", "", "rook", "different work")
	if s1.ID != s2.ID || s1.ID == s3.ID {
		t.Fatalf("spawn ids: %q %q %q", s1.ID, s2.ID, s3.ID)
	}
	for _, bad := range [][4]string{
		{"shell", "sess-1", "", ""}, // not a kind, never will be
		{"", "sess-1", "", ""},      // no kind
		{"compact", "", "", ""},     // no session
		{"compact", strings.Repeat("x", MaxAskIDLen+1), "", ""}, // oversize handle
		{"compact", "sess-1", "", "sneaky prompt"},              // fields not its own
		{"resume", "sess-1", "rook", ""},                        // fields not its own
		{"spawn", "", "", "prompt without a workspace"},
		{"spawn", "sess-1", "rook", ""}, // a spawn names no session
		{"spawn", "", "rook", strings.Repeat("p", MaxAnswerLen+1)},
	} {
		if _, err := ValidCommand(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Errorf("ValidCommand(%q, %q, %q, %q) accepted", bad[0], bad[1], bad[2], bad[3])
		}
	}
}

// Clamp bounds the new agent fields like the old: a hostile ctxPct is
// zeroed, an oversize session id is clipped.
func TestClampBoundsIDAndCtxPct(t *testing.T) {
	s := &Status{Workspaces: []Workspace{{Name: "w", Agents: []Agent{
		{ID: strings.Repeat("a", 500), State: "working", CtxPct: 4000},
		{ID: "ok", State: "working", CtxPct: 141},
	}}}}
	s.Clamp()
	a := s.Workspaces[0].Agents
	if len(a[0].ID) != MaxAskIDLen || a[0].CtxPct != 0 {
		t.Fatalf("hostile agent survived clamp: %+v", a[0])
	}
	if a[1].CtxPct != 141 {
		t.Fatalf(">100 is honest and must survive: %+v", a[1])
	}
}

// The digest is generated prose from the machine, so every dimension
// gets a lid — and a digest that clamps down to no headline was never
// a digest at all.
func TestClampBoundsDigests(t *testing.T) {
	long := strings.Repeat("x", 1000)
	s := &Status{Workspaces: []Workspace{{Name: "w", Agents: []Agent{
		{State: "working", Digest: &AgentDigest{
			Headline: long,
			Bullets:  []string{long, "b", "c", "d", "e", "f", "g", "h"},
		}},
		{State: "working", Digest: &AgentDigest{Headline: "", Bullets: []string{"orphan"}}},
		{State: "working"},
	}}}}
	s.Clamp()
	a := s.Workspaces[0].Agents
	d := a[0].Digest
	if d == nil || len(d.Headline) != 400 || len(d.Bullets) != 6 || len(d.Bullets[0]) != 400 {
		t.Fatalf("hostile digest survived clamp: %+v", d)
	}
	if a[1].Digest != nil {
		t.Fatalf("a headline-less digest must drop whole: %+v", a[1].Digest)
	}
	if a[2].Digest != nil {
		t.Fatalf("no digest must stay no digest: %+v", a[2].Digest)
	}
}
