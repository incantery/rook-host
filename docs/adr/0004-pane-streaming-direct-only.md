# 4. Pane streaming rides the direct link only

Date: 2026-08-10

## Status

Accepted

## Context

The projection deliberately carries states, titles, and pending asks —
never terminal contents. That line made the phone's session screen a
void: you answer an ask blind and never see it land. The fix is a live
view of the pane itself, `WatchPane(session_id)`, streaming the host
emulator's own styled cell grid.

Terminal contents are the highest-sensitivity data the host has —
secrets scroll through panes. So the stream gets three walls, each a
different mechanism:

1. **Rail**: pane frames exist only in `rook.link.v1`, the QR-pinned
   direct connection. There is no cloud counterpart, no relay path, and
   the projection types that ride the cloud rail never embed a
   `PaneFrame`. Adding one would be a reviewed protocol change against
   this ADR, not a field.
2. **Capability**: a new `session.read`, checked live per stream like
   every other RPC. Revocation and re-pairing kill open pane streams in
   the same breath as everything else.
3. **Production**: the host only produces frames while a watcher
   exists — the hub drives the source on first-subscribe /
   last-unsubscribe edges, and the retained frame is dropped with the
   last watcher rather than served stale later.

The phone names *sessions*, never panes: the session id is the same
handle the projection reports, and the host resolves it to a pane per
frame. A session whose pane is momentarily unresolvable keeps its
stream open on heartbeats — frames resume when it reappears.

Frames are display-ready: the host emulator resolves palette indices,
inverse, and faint into final RGB before the wire, so the surface is a
dumb grid view — no second emulator, no VT parsing, no palette table.
Snapshots only, latest-wins coalesced, viewport only. No scrollback and
no deltas in v1; a delta kind can join the response enum compatibly.

## Alternatives rejected

- **Pane frames over the cloud rail**: turns rook-cloud into a
  terminal-contents custodian — storage, retention, and breach surface
  for the one data class the projection line existed to keep home.
- **Raw VT bytes to the phone**: needs a second emulator (libghostty on
  iOS or a Swift VT parser) that must agree with the host's forever.
  One emulator, one truth; the phone renders cells.
- **Always-on streaming**: producing frames nobody watches costs host
  CPU under the session lock and widens the window where contents are
  in flight. Watcher-edge production keeps the default state "nothing
  leaves the machine".

## Consequences

- Devices paired before `session.read` existed do not gain it
  retroactively — re-pairing is the upgrade path, and the surface says
  so instead of failing quietly.
- A surface out of direct-link range loses the terminal view but keeps
  the projection and its verbs — degradation is a feature loss, never a
  correctness loss.
- The per-session monotonic seq gives reconnects the same collapse
  rule as WatchStatus: newest wins, no history, no gap replay.
