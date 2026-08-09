package link

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// tokens is the session-token store: opaque handle → authenticated
// device, held in memory only. A token is a HANDLE, not an authority —
// every RPC still checks the registry — so losing them all to a
// restart costs each device one cheap re-authentication, and
// revocation does not wait for any expiry.
type tokens struct {
	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	deviceID string
	expires  time.Time
}

// nonces is the challenge store: single-use, short-lived, bound to the
// device the challenge was minted for.
type nonces struct {
	mu     sync.Mutex
	issued map[string]nonce // key: base64url of the nonce bytes
}

type nonce struct {
	deviceID string
	expires  time.Time
}

const (
	tokenTTL = 24 * time.Hour
	nonceTTL = 60 * time.Second
)

func newTokens() *tokens { return &tokens{sessions: map[string]session{}} }
func newNonces() *nonces { return &nonces{issued: map[string]nonce{}} }

func (t *tokens) mint(deviceID string, now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	exp := now.Add(tokenTTL)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[tok] = session{deviceID: deviceID, expires: exp}
	return tok, exp, nil
}

// resolve maps a presented token to its device, or "" if unknown or
// expired. Expired entries are removed on sight — the map stays the
// size of the live session set.
func (t *tokens) resolve(tok string, now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[tok]
	if !ok {
		return ""
	}
	if !now.Before(s.expires) {
		delete(t.sessions, tok)
		return ""
	}
	return s.deviceID
}

// dropDevice kills every session a device holds — the token half of
// revocation.
func (t *tokens) dropDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for tok, s := range t.sessions {
		if s.deviceID == deviceID {
			delete(t.sessions, tok)
		}
	}
}

func (n *nonces) mint(deviceID string, now time.Time) ([]byte, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, time.Time{}, err
	}
	exp := now.Add(nonceTTL)
	n.mu.Lock()
	defer n.mu.Unlock()
	// Sweep the expired while we are here; challenges are rare.
	for k, v := range n.issued {
		if !now.Before(v.expires) {
			delete(n.issued, k)
		}
	}
	n.issued[base64.RawURLEncoding.EncodeToString(raw)] = nonce{deviceID: deviceID, expires: exp}
	return raw, exp, nil
}

// consume removes the nonce whether or not the caller's signature will
// verify — a failed authentication burns the challenge, replay gets
// nothing — and reports whether it was live and minted for deviceID.
func (n *nonces) consume(raw []byte, deviceID string, now time.Time) bool {
	key := base64.RawURLEncoding.EncodeToString(raw)
	n.mu.Lock()
	defer n.mu.Unlock()
	v, ok := n.issued[key]
	if !ok {
		return false
	}
	delete(n.issued, key)
	return now.Before(v.expires) && v.deviceID == deviceID
}
