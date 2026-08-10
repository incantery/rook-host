package link

import (
	"sync"

	"github.com/incantery/rook-host/projection"
)

// PaneSource is the machine side of pane streaming: the hub tells it
// when a session gains its first watcher and loses its last one, and
// the source pushes frames back through Server.PublishPane in between.
// Both calls are made under the hub's internal lock — implementations
// must return quickly and must never call PublishPane synchronously
// from either (spawn, don't stream, from Open).
type PaneSource interface {
	// Open starts producing frames for sessionID. An error refuses the
	// first watcher; the source stays closed for that session.
	Open(sessionID string) error
	// Close stops producing frames for sessionID.
	Close(sessionID string)
}

// paneHub fans pane frames out per watched session. Same semantics as
// the status hub — latest wins, no history, buffer-1 coalescing — but
// keyed by session: each watched session has its own retained frame
// and its own monotonic seq, and the hub drives the PaneSource on
// watcher-count edges so the machine only produces frames somebody is
// looking at.
type paneHub struct {
	mu       sync.Mutex
	source   PaneSource // nil = pane streaming unimplemented
	sessions map[string]*paneSession
}

// paneSession is one watched session's fan-out state. It outlives its
// watchers so seq stays monotonic across re-watches; the retained
// frame does not — stale pane contents are dropped with the last
// watcher rather than served as an opening frame later.
type paneSession struct {
	current *paneFrameMsg
	seq     uint64
	subs    map[*paneSub]struct{}
	// open tracks whether the source has been told to produce — the
	// edge, explicitly, so a revocation racing a stream teardown cannot
	// Close twice.
	open bool
}

type paneSub struct {
	deviceID string
	// updates carries at most one pending frame; publishing over a
	// full buffer replaces the pending frame (latest wins).
	updates chan paneFrameMsg
	// gone is closed exactly once — by revocation or by unsubscribe.
	gone chan struct{}
	once sync.Once
}

type paneFrameMsg struct {
	frame projection.PaneFrame
	seq   uint64
}

func newPaneHub(source PaneSource) *paneHub {
	return &paneHub{source: source, sessions: map[string]*paneSession{}}
}

// publish clamps the frame, retains it for the session, and offers it
// to every watcher. Frames for sessions nobody watches are dropped —
// the source should not be producing them, but a race across the
// Close edge is harmless.
func (h *paneHub) publish(sessionID string, f projection.PaneFrame) {
	f.Clamp()
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok || len(sess.subs) == 0 {
		return
	}
	sess.seq++
	msg := paneFrameMsg{frame: f, seq: sess.seq}
	sess.current = &msg
	for sub := range sess.subs {
		select {
		case sub.updates <- msg:
		default:
			// Buffer full: drain the stale frame and offer the fresh one.
			select {
			case <-sub.updates:
			default:
			}
			select {
			case sub.updates <- msg:
			default:
			}
		}
	}
}

// subscribe registers a watcher for sessionID, opening the source on
// the first one. Returns the subscriber and the retained frame, if
// any — taken under the same lock, so nothing published between
// "snapshot" and "subscribed" can be missed.
func (h *paneHub) subscribe(deviceID, sessionID string) (*paneSub, *paneFrameMsg, error) {
	sub := &paneSub{
		deviceID: deviceID,
		updates:  make(chan paneFrameMsg, 1),
		gone:     make(chan struct{}),
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok {
		sess = &paneSession{subs: map[*paneSub]struct{}{}}
		h.sessions[sessionID] = sess
	}
	if !sess.open && h.source != nil {
		if err := h.source.Open(sessionID); err != nil {
			return nil, nil, err
		}
		sess.open = true
	}
	sess.subs[sub] = struct{}{}
	return sub, sess.current, nil
}

func (h *paneHub) unsubscribe(sessionID string, sub *paneSub) {
	h.mu.Lock()
	if sess, ok := h.sessions[sessionID]; ok {
		delete(sess.subs, sub)
		h.closeIfUnwatchedLocked(sessionID, sess)
	}
	h.mu.Unlock()
	sub.close()
}

// dropDevice terminates every pane stream a device holds — the
// streaming half of revocation, and the re-pair path.
func (h *paneHub) dropDevice(deviceID string) {
	h.mu.Lock()
	var doomed []*paneSub
	for sessionID, sess := range h.sessions {
		for sub := range sess.subs {
			if sub.deviceID == deviceID {
				doomed = append(doomed, sub)
				delete(sess.subs, sub)
			}
		}
		h.closeIfUnwatchedLocked(sessionID, sess)
	}
	h.mu.Unlock()
	for _, sub := range doomed {
		sub.close()
	}
}

// closeIfUnwatchedLocked handles the last-watcher edge: tell the
// source to stop, and drop the retained frame so a later re-watch
// opens on fresh truth instead of a stale grid.
func (h *paneHub) closeIfUnwatchedLocked(sessionID string, sess *paneSession) {
	if len(sess.subs) != 0 || !sess.open {
		return
	}
	sess.current = nil
	sess.open = false
	if h.source != nil {
		h.source.Close(sessionID)
	}
}

func (s *paneSub) close() {
	s.once.Do(func() { close(s.gone) })
}
