// Package link is the host side of the rook.link.v1 rail: the
// pre-session pairing surface, the token-gated session surface, the
// status hub that fans snapshots out to watchers, and the seam the
// embedding host implements to actually deliver effects.
//
// The package owns protocol truth (auth, capabilities, validation,
// natural keys) and owns NO machine truth: what agents exist comes in
// through Publish, and what happens at the keyboard goes out through
// Executor. That split is the architecture — this package can be
// audited without seeing a transcript scanner, and the scanner never
// learns the wire.
package link

import (
	"context"

	"github.com/incantery/rook-host/projection"
)

// Executor is what the embedding host supplies: the two effect verbs a
// remote surface may request. Implementations deliver through their
// own local gates (foreground checks, human-typing-wins, bounded
// retries) and own at-most-once delivery — the natural key on a
// Command and the AskID on an Answer are the journal keys, shared with
// every other rail, so a request that raced in twice (or over two
// rails) resolves as Duplicate rather than a double-type.
//
// Implementations must not panic and must respect ctx — the server
// calls these synchronously inside an RPC deadline.
type Executor interface {
	// Answer delivers a reply to a pending ask.
	Answer(ctx context.Context, a projection.Answer) Outcome
	// Execute runs one validated, allowlisted command.
	Execute(ctx context.Context, c projection.Command) Outcome
}

// Disposition is what actually happened at the keyboard.
type Disposition int

const (
	// Delivered: the effect landed.
	Delivered Disposition = iota + 1
	// Duplicate: the journal had already seen this key; the first
	// submission won and this one changed nothing. Success, loudly.
	Duplicate
	// Dropped: the effect could not apply — target gone, gates closed
	// after bounded retries. Note says why.
	Dropped
)

// Outcome is an Executor's report.
type Outcome struct {
	Disposition Disposition
	// Note is surfaced verbatim on the remote surface when the
	// disposition needs explaining ("no agent pane for that ask").
	Note string
}
