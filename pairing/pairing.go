// Package pairing is the enrollment ceremony: a human opens a window
// on the host, the host mints a one-time secret, the secret rides a QR
// code to the device, and the device redeems it — once, soon, or not
// at all. The window is the consent; the secret is only the proof that
// the device saw the QR the human displayed.
package pairing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TTL is how long an open window lasts. Long enough to fetch a phone
// from the other room; short enough that a forgotten window is not a
// standing invitation.
const TTL = 2 * time.Minute

const secretLen = 16

// Manager holds at most one pairing window. Opening a new one closes
// the old — two concurrent windows means two QRs in the world and no
// way to say which one the human is holding.
type Manager struct {
	mu      sync.Mutex
	secret  string
	expires time.Time
}

// Open mints a fresh window and returns its secret (base64url).
func (m *Manager) Open(now time.Time) (string, error) {
	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secret = s
	m.expires = now.Add(TTL)
	return s, nil
}

// Close shuts the window without a redemption (human dismissed the QR).
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secret = ""
}

// OpenNow reports whether a window is currently open.
func (m *Manager) OpenNow(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secret != "" && now.Before(m.expires)
}

// Redeem burns the window if the presented secret matches and the
// window is live. Single-use by construction: success or failure
// against a live window, matched or not, leaves at most the one window
// standing, and a match always closes it.
func (m *Manager) Redeem(secret string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secret == "" || !now.Before(m.expires) {
		return false
	}
	ok := subtle.ConstantTimeCompare([]byte(m.secret), []byte(secret)) == 1
	if ok {
		m.secret = "" // burned
	}
	return ok
}

// QR is everything the pairing code carries. All values are
// base64url/base32/digits or %-escaped, so the composed URL is both
// QR-friendly and shell-safe by construction.
//
// HostID, SPKIPin, Secret, and Port are the contract; the rest are
// optional hints, and OMITTING them is a feature: every byte in this
// URL is QR modules, and QR modules are terminal columns. The phone
// learns the display name from GetHostInfo and the trust domain from
// PairResponse — both better sources than a QR snapshot anyway.
type QR struct {
	HostID        string
	TrustDomainID string // optional; PairResponse is authoritative
	HostName      string // optional; GetHostInfo is authoritative
	SPKIPin       string // base64url sha256 of the TLS leaf SPKI
	Secret        string // the window's one-time secret
	Port          int
	Addrs         []string // direct address hints; Bonjour is the fallback
}

// URL composes the rook-link://pair form the phone parses. Empty
// optional fields are omitted, not emitted empty.
func (q QR) URL() string {
	v := url.Values{}
	v.Set("v", "1")
	v.Set("hid", q.HostID)
	if q.TrustDomainID != "" {
		v.Set("td", q.TrustDomainID)
	}
	if q.HostName != "" {
		v.Set("n", q.HostName)
	}
	v.Set("spki", q.SPKIPin)
	v.Set("s", q.Secret)
	v.Set("p", strconv.Itoa(q.Port))
	if len(q.Addrs) > 0 {
		v.Set("a", strings.Join(q.Addrs, ","))
	}
	return "rook-link://pair?" + v.Encode()
}

// ParseURL is the inverse — used by the Go test client and the tests;
// the phone reimplements this trivially in Swift.
func ParseURL(s string) (QR, error) {
	u, err := url.Parse(s)
	if err != nil {
		return QR{}, err
	}
	if u.Scheme != "rook-link" || u.Host != "pair" {
		return QR{}, fmt.Errorf("pairing: not a rook-link pair URL")
	}
	v := u.Query()
	if v.Get("v") != "1" {
		return QR{}, fmt.Errorf("pairing: unknown QR version %q", v.Get("v"))
	}
	port, err := strconv.Atoi(v.Get("p"))
	if err != nil || port <= 0 || port > 65535 {
		return QR{}, fmt.Errorf("pairing: bad port %q", v.Get("p"))
	}
	q := QR{
		HostID:        v.Get("hid"),
		TrustDomainID: v.Get("td"),
		HostName:      v.Get("n"),
		SPKIPin:       v.Get("spki"),
		Secret:        v.Get("s"),
		Port:          port,
	}
	if a := v.Get("a"); a != "" {
		q.Addrs = strings.Split(a, ",")
	}
	if q.HostID == "" || q.SPKIPin == "" || q.Secret == "" {
		return QR{}, fmt.Errorf("pairing: QR missing hid/spki/s")
	}
	return q, nil
}
