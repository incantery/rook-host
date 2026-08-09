package link

import (
	"sync"
	"time"

	"github.com/incantery/rook-host/projection"
)

// hub holds the latest projection snapshot and fans updates out to
// watchers. Semantics are deliberately "latest wins, no history": a
// slow watcher skips intermediate snapshots rather than queueing them,
// and a reconnecting watcher starts from the current truth. seq is
// monotonic per host process so a surface holding N can drop any frame
// ≤ N.
type hub struct {
	mu      sync.Mutex
	current projection.Status
	at      time.Time // when current was published
	seq     uint64
	subs    map[*subscriber]struct{}
}

type subscriber struct {
	deviceID string
	// updates carries at most one pending snapshot; publishing over a
	// full buffer replaces the pending frame (latest wins).
	updates chan frame
	// gone is closed exactly once — by revocation or by unsubscribe.
	gone chan struct{}
	once sync.Once
}

type frame struct {
	status projection.Status
	at     time.Time
	seq    uint64
}

func newHub() *hub {
	return &hub{subs: map[*subscriber]struct{}{}}
}

// publish clamps the snapshot, makes it current, and offers it to
// every live watcher. Returns the assigned seq.
func (h *hub) publish(s projection.Status, at time.Time) uint64 {
	s.Clamp()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	h.current = s
	h.at = at
	f := frame{status: s, at: at, seq: h.seq}
	for sub := range h.subs {
		select {
		case sub.updates <- f:
		default:
			// Buffer full: drain the stale frame and offer the fresh one.
			select {
			case <-sub.updates:
			default:
			}
			select {
			case sub.updates <- f:
			default:
			}
		}
	}
	return h.seq
}

// snapshot returns the current truth.
func (h *hub) snapshot() (projection.Status, time.Time, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current, h.at, h.seq
}

// subscribe registers a watcher for deviceID and returns it alongside
// the opening snapshot — taken under the same lock, so nothing
// published between "snapshot" and "subscribed" can be missed.
func (h *hub) subscribe(deviceID string) (*subscriber, frame) {
	sub := &subscriber{
		deviceID: deviceID,
		updates:  make(chan frame, 1),
		gone:     make(chan struct{}),
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs[sub] = struct{}{}
	return sub, frame{status: h.current, at: h.at, seq: h.seq}
}

func (h *hub) unsubscribe(sub *subscriber) {
	h.mu.Lock()
	delete(h.subs, sub)
	h.mu.Unlock()
	sub.close()
}

// dropDevice terminates every stream a device holds — the streaming
// half of revocation.
func (h *hub) dropDevice(deviceID string) {
	h.mu.Lock()
	var doomed []*subscriber
	for sub := range h.subs {
		if sub.deviceID == deviceID {
			doomed = append(doomed, sub)
			delete(h.subs, sub)
		}
	}
	h.mu.Unlock()
	for _, sub := range doomed {
		sub.close()
	}
}

func (s *subscriber) close() {
	s.once.Do(func() { close(s.gone) })
}
