# ADR 0004 — The Claude Code adapter drives the TUI only (MVP)

**Status:** accepted (2026-07-26)

## Context

Rook's thesis is that it drives Claude Code the way a person does — a PTY
running the interactive TUI. If Anthropic ever splits billing or terms
between headless/SDK usage (`-p`, `stream-json`, Agent SDK) and
interactive TUI usage, an automation built on headless mode lands on the
wrong side of that line; one built on the TUI keeps working on the user's
subscription. NEXT.md §8.2 hedged, ranking `stream-json` third in its
integration hierarchy — but stream-json requires headless mode, exactly
the mode at risk.

## Decision

For the MVP, the Claude Code adapter is **TUI-only**: PTY + interactive
session, `Send`/`Interrupt` as terminal input, `Resume` via TUI resume.
No `-p`, no `stream-json`, no Agent SDK sessions. The integration
hierarchy becomes: Rook MCP tools → hooks → PTY/process state → terminal
parsing as last-resort fallback. Hooks and MCP both work in interactive
sessions and remain the structured sources of truth — driving the TUI
never means scraping the TUI; terminal text stays presentation.

Build to interfaces (the `AgentProvider` seam, NEXT.md §8.1): keep
Claude-specific and PTY-specific types out of workflow/event schemas so an
API-billed adapter can be added later without touching the runtime.

## Consequences

- The version/capability probe and `IdleUncertain` reconciliation are
  load-bearing: hooks + PTY + process health are the only liveness
  signals. Pin a supported Claude Code version range.
- Structured completion comes exclusively from the `rook.complete` MCP
  tool; no `--output-format` anywhere.
- Terminal attach/takeover is simpler: there is exactly one session mode,
  and the human attaches to the same live TUI Rook drives.
- Residual bet: the billing line is drawn technical (TUI vs headless),
  not behavioral (human vs automation). The interface seam is the hedge.
