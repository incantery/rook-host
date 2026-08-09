# ADR 0003 — Cloud is coordination authority; the IDE is machine authority

**Status:** accepted (2026-07-26)

## Context

Rook Cloud orchestrates work that executes on a user's machine through
Rook IDE. A design where Cloud "runs commands remotely" makes the user's
machine an extension of the server — every Cloud compromise, bug, or stale
decision reaches the filesystem directly (NEXT.md §4).

## Decision

Cloud may **request**; only the IDE may **execute**. Concretely:

- Cloud owns durable task state, workflow runs, policies-as-filters,
  decisions, approvals, and the command ledger.
- The IDE owns local effects: processes, PTYs, worktrees, secrets,
  filesystem and network enforcement — and evaluates every requested
  action under *current local policy* before executing. A Cloud "allow"
  is a prerequisite, never a mandate; local deny always wins.
- The boundary is a distributed-systems contract, not a remote shell:
  commands are durable, signed, idempotent, fenced (monotonic tokens),
  version-checked, and expiring. At-least-once delivery, at-most-once
  local effect per command ID, enforced by the IDE's durable command
  journal. No generic execute-shell command crosses the boundary, ever.
- A live socket is a latency optimization; correctness comes from the
  ledger + journal + cursor reconciliation on reconnect.

## Consequences

- The IDE keeps a local command journal and records receipt before any
  effect; duplicate delivery returns the recorded result.
- Secrets never appear in Cloud state — opaque handles resolve locally.
- Every typed command needs an idempotency/reconciliation story before it
  exists; that friction is the feature.
