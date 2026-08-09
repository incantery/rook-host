// Package projection is the shared vocabulary of the live rail: the
// bounded snapshot a machine publishes about itself (Status), and the
// two instruction shapes a remote surface may send back (Answer,
// Command). Every rail — cloud outbox or direct link — speaks exactly
// these types, so the clamps, the allowlist, and the natural keys have
// a single definition.
//
// The detail level is a decided line, not an accident: states, titles,
// and pending ask text come up; foreground commands, terminal contents,
// and anything else from the machine stay home.
//
// The bson tags are rook-cloud's storage shape for these values and are
// inert everywhere else. They stay because dropping them would silently
// rename Mongo fields under the one consumer that persists snapshots.
package projection

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxAskIDLen      = 128
	MaxAnswerLen     = 4096
	MaxAnswerPending = 20
)

var (
	ErrBadAnswer      = errors.New("answer needs an askId (≤128 bytes) and text (≤4096 bytes)")
	ErrAnswerConflict = errors.New("that ask already has a pending answer, or the outbox is full")
)

// Answer is one reply crossing from a remote surface to the machine
// that reported the ask. AskID is the machine's own stable handle for
// the ask (it minted it in a status snapshot); no rail interprets it.
type Answer struct {
	AskID string    `bson:"askId" json:"askId"`
	Text  string    `bson:"text" json:"text"`
	At    time.Time `bson:"at" json:"at"`
}

// ValidAnswer normalizes and checks a phone-authored answer.
func ValidAnswer(askID, text string) (Answer, error) {
	askID = strings.TrimSpace(askID)
	text = strings.TrimSpace(text)
	if askID == "" || len(askID) > MaxAskIDLen || text == "" || len(text) > MaxAnswerLen {
		return Answer{}, ErrBadAnswer
	}
	return Answer{AskID: askID, Text: text, At: time.Now().UTC()}, nil
}

// Command is one phone-issued instruction for a machine — the verb
// half of what Answer started. A rail REQUESTS, the machine decides:
// every command still crosses the machine's local gates (agent-TUI
// foreground, human-typing-wins), and an inapplicable one is acked
// away with a note, never forced. Kind is from a short allowlist,
// deliberately — "run this shell command" will never be a Kind, and no
// field here is ever a shell string: the machine builds what it runs
// from its own local data, and a spawn's Prompt reaches the agent as
// TYPED TEXT, never interpolated. The ID is natural (kind + its
// target), which makes "one pending per target" a filter instead of a
// transaction — and makes a command delivered over two rails one
// command.
type Command struct {
	ID   string `bson:"id" json:"id"`
	Kind string `bson:"kind" json:"kind"`
	// SessionID names the target session (compact, resume).
	SessionID string `bson:"sessionId,omitempty" json:"sessionId,omitempty"`
	// Workspace and Prompt belong to spawn: a workspace name the
	// machine itself reported, and the first thing to say to the new
	// session — typed in through session.send, so it is data there.
	Workspace string    `bson:"workspace,omitempty" json:"workspace,omitempty"`
	Prompt    string    `bson:"prompt,omitempty" json:"prompt,omitempty"`
	At        time.Time `bson:"at" json:"at"`
}

// CommandKinds is the allowlist. Growing it is a deliberate act with
// a review, not a string a client sends.
var CommandKinds = []string{"compact", "resume", "spawn"}

const MaxCommandPending = 20

var (
	ErrBadCommand      = errors.New("command needs a known kind and its target: sessionId (≤128 bytes) for compact/resume, workspace (≤200 bytes) and an optional prompt (≤4096 bytes) for spawn")
	ErrCommandConflict = errors.New("that command is already pending, or the outbox is full")
)

// ValidCommand normalizes and checks a phone-issued command. Each kind
// keeps exactly its own fields — a compact carrying a prompt is a
// confused client, refused rather than half-obeyed.
func ValidCommand(kind, sessionID, workspace, prompt string) (Command, error) {
	kind = strings.TrimSpace(kind)
	sessionID = strings.TrimSpace(sessionID)
	workspace = strings.TrimSpace(workspace)
	prompt = strings.TrimSpace(prompt)
	now := time.Now().UTC()
	switch kind {
	case "compact", "resume":
		if sessionID == "" || len(sessionID) > MaxAskIDLen || workspace != "" || prompt != "" {
			return Command{}, ErrBadCommand
		}
		return Command{ID: kind + ":" + sessionID, Kind: kind, SessionID: sessionID, At: now}, nil
	case "spawn":
		if workspace == "" || len(workspace) > 200 || len(prompt) > MaxAnswerLen || sessionID != "" {
			return Command{}, ErrBadCommand
		}
		return Command{
			ID: "spawn:" + workspace + ":" + fnv8(prompt), Kind: kind,
			Workspace: workspace, Prompt: prompt, At: now,
		}, nil
	}
	return Command{}, ErrBadCommand
}

// fnv8 folds a string to eight hex digits — an identity for dedup
// (the same spawn double-tapped is one spawn), not a defense.
func fnv8(s string) string {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%08x", uint32(h^(h>>32)))
}

// Status is one machine's snapshot of what is going on: every workspace
// with live agents, and what each agent is doing. Last write wins — there
// is no history here, deliberately; this is "what is happening now", and
// the event-sourced version of this feature is a different, larger thing.
type Status struct {
	Hostname    string `bson:"hostname,omitempty" json:"hostname,omitempty"`
	RookVersion string `bson:"rookVersion,omitempty" json:"rookVersion,omitempty"`
	// HostID is the machine's durable link identity
	// (identity.HostIDFor) when the machine has one. It rides EVERY
	// rail so a surface seeing this machine twice — once via cloud,
	// once via direct link — can prove both are one machine and
	// collapse them. Hostnames are display; this is identity.
	HostID     string      `bson:"hostId,omitempty" json:"hostId,omitempty"`
	Workspaces []Workspace `bson:"workspaces,omitempty" json:"workspaces,omitempty"`
}

type Workspace struct {
	Name      string  `bson:"name" json:"name"`
	Branch    string  `bson:"branch,omitempty" json:"branch,omitempty"`
	Attention int     `bson:"attention,omitempty" json:"attention,omitempty"`
	Agents    []Agent `bson:"agents,omitempty" json:"agents,omitempty"`
}

type Agent struct {
	// ID is the machine's session id — the handle a Command names.
	// Absent on old rook versions, and everything else still works.
	ID    string `bson:"id,omitempty" json:"id,omitempty"`
	State string `bson:"state" json:"state"` // working | needs_input | quiet
	Title string `bson:"title,omitempty" json:"title,omitempty"`
	Ask   string `bson:"ask,omitempty" json:"ask,omitempty"`
	// AskID is the machine-minted stable handle an answer names. Present
	// exactly when Ask is — an ask you cannot answer is a headline, and
	// a fleet surface renders it as one.
	AskID   string  `bson:"askId,omitempty" json:"askId,omitempty"`
	Model   string  `bson:"model,omitempty" json:"model,omitempty"`
	CostUSD float64 `bson:"costUsd,omitempty" json:"costUsd,omitempty"`
	// CtxPct is context occupancy as a percent of the model's window,
	// measured by the machine from the session's own usage records.
	// 0 means unreported; >100 is possible and honest (the machine's
	// window table was wrong, and that should look wrong).
	CtxPct int `bson:"ctxPct,omitempty" json:"ctxPct,omitempty"`
	// Digest is the machine's membrane artifact: the agent plugin's
	// STE compression of the session's last finished turn. It is the
	// one field here that is GENERATED prose rather than raw — the
	// phone triages by headline, and the raw turn it compresses never
	// leaves the machine.
	Digest    *AgentDigest `bson:"digest,omitempty" json:"digest,omitempty"`
	LastEvent time.Time    `bson:"lastEvent,omitempty" json:"lastEvent,omitzero"`
}

// AgentDigest is a headline plus bullets — STE discipline on the
// machine side keeps them terse; the clamp here only guards against a
// client that ignored it.
type AgentDigest struct {
	Headline string    `bson:"headline" json:"headline"`
	Bullets  []string  `bson:"bullets,omitempty" json:"bullets,omitempty"`
	At       time.Time `bson:"at,omitempty" json:"at,omitzero"`
}

// Clamp caps every unbounded dimension of a snapshot in place. A
// transport's body limit bounds the total bytes; this bounds what of
// them we keep, so one misbehaving client cannot grow a stored row or
// a fan-out frame without limit.
func (s *Status) Clamp() {
	const (
		maxWorkspaces = 100
		maxAgents     = 50
		maxShort      = 200  // names, titles, models
		maxAsk        = 2000 // ask text is the one field worth reading in full
	)
	s.Hostname = clip(s.Hostname, maxShort)
	s.RookVersion = clip(s.RookVersion, maxShort)
	s.HostID = clip(s.HostID, MaxAskIDLen)
	if len(s.Workspaces) > maxWorkspaces {
		s.Workspaces = s.Workspaces[:maxWorkspaces]
	}
	for i := range s.Workspaces {
		w := &s.Workspaces[i]
		w.Name = clip(w.Name, maxShort)
		w.Branch = clip(w.Branch, maxShort)
		if len(w.Agents) > maxAgents {
			w.Agents = w.Agents[:maxAgents]
		}
		for j := range w.Agents {
			a := &w.Agents[j]
			a.ID = clip(a.ID, MaxAskIDLen)
			a.State = clip(a.State, maxShort)
			a.Title = clip(a.Title, maxShort)
			a.Ask = clip(a.Ask, maxAsk)
			a.AskID = clip(a.AskID, MaxAskIDLen)
			a.Model = clip(a.Model, maxShort)
			if a.CtxPct < 0 || a.CtxPct > 999 {
				a.CtxPct = 0
			}
			if d := a.Digest; d != nil {
				const (
					maxHeadline = 400 // ~25 STE words with slack
					maxBullets  = 6
					maxBullet   = 400
				)
				d.Headline = clip(d.Headline, maxHeadline)
				if len(d.Bullets) > maxBullets {
					d.Bullets = d.Bullets[:maxBullets]
				}
				for k := range d.Bullets {
					d.Bullets[k] = clip(d.Bullets[k], maxBullet)
				}
				// A digest with nothing to headline is not a digest.
				if d.Headline == "" {
					a.Digest = nil
				}
			}
		}
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// cut on a rune boundary so a clipped title stays valid UTF-8
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
