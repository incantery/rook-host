// Package registry is the host's paired-device book: which device
// keys may open a link, and what each one may do. It is the live
// authority for every session-surface RPC — a session token is a
// handle into this registry, never a cached verdict — which is what
// makes revocation take effect on the revoked device's next call
// rather than at some expiry.
//
// Storage is one JSON file, written atomically at 0600. A host pairs
// a handful of devices in its lifetime; the registry's job is to be
// obviously correct, not fast.
package registry

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// The capability vocabulary. Growing it is a protocol change with a
// review, exactly like the command allowlist.
const (
	// CapStatusRead: receive the projection (GetStatus, WatchStatus).
	CapStatusRead = "status.read"
	// CapAgentAnswer: reply to an agent's pending ask.
	CapAgentAnswer = "agent.answer"
	// CapAgentCommand: send allowlisted commands (compact/resume/spawn).
	CapAgentCommand = "agent.command"
	// CapSessionRead: watch a session's live pane contents (WatchPane).
	// Direct link only — pane frames never ride the cloud rail.
	CapSessionRead = "session.read"
)

// DefaultCapabilities is the V1 pairing grant: everything. The
// registry stores per-device sets and the interceptor enforces them
// from day one, so tightening is a policy decision, not a protocol
// change.
var DefaultCapabilities = []string{CapStatusRead, CapAgentAnswer, CapAgentCommand, CapSessionRead}

// KnownCapability reports whether s is in the vocabulary at all.
func KnownCapability(s string) bool {
	return s == CapStatusRead || s == CapAgentAnswer || s == CapAgentCommand || s == CapSessionRead
}

var (
	ErrNotFound = errors.New("registry: no such device")
	ErrRevoked  = errors.New("registry: device is revoked")
)

// Device is one paired remote surface.
type Device struct {
	// ID is derived from the public key (identity.DeviceIDFor), so both
	// sides always compute the same handle.
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model,omitempty"`
	// PublicKey is the device's Ed25519 key — the only secret-shaped
	// thing here is that there is nothing secret here: a stolen
	// registry file contains nothing presentable.
	PublicKey    []byte     `json:"publicKey"`
	Capabilities []string   `json:"capabilities"`
	PairedAt     time.Time  `json:"pairedAt"`
	LastSeenAt   time.Time  `json:"lastSeenAt,omitzero"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
}

// Key returns the device's public key in its typed form.
func (d Device) Key() ed25519.PublicKey { return ed25519.PublicKey(d.PublicKey) }

// Revoked reports whether the device has been revoked. A revoked
// device stays in the book as a tombstone — re-pairing the same key is
// a deliberate human act with a fresh QR, not a retry.
func (d Device) Revoked() bool { return d.RevokedAt != nil }

// Registry is the in-memory book plus its file. All methods are safe
// for concurrent use.
type Registry struct {
	mu      sync.Mutex
	path    string
	devices map[string]*Device
}

type registryFile struct {
	Version int      `json:"version"`
	Devices []Device `json:"devices"`
}

// Open loads the registry at path, or starts an empty one if the file
// does not exist. A file that exists but does not parse is an error —
// silently starting empty would un-pair every device.
func Open(path string) (*Registry, error) {
	r := &Registry{path: path, devices: map[string]*Device{}}
	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return r, nil
	case err != nil:
		return nil, err
	}
	var f registryFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("registry: %s is not JSON: %w", path, err)
	}
	for i := range f.Devices {
		d := f.Devices[i]
		r.devices[d.ID] = &d
	}
	return r, nil
}

// Add registers a paired device, REPLACING any existing registration
// for the same key — live or tombstoned. Pairing again is not an
// attack this refusal could stop: the enrollment already proves
// possession of the very key being replaced, inside a window a human
// just opened, which is strictly stronger consent than the original
// pairing had. Refusing it only strands a phone whose cached
// connection details went stale.
//
// The capability set is filtered to the known vocabulary; an empty
// result means the device asked for nothing recognizable and is
// refused.
func (r *Registry) Add(d Device) error {
	if len(d.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("registry: device key is %d bytes, want %d", len(d.PublicKey), ed25519.PublicKeySize)
	}
	caps := make([]string, 0, len(d.Capabilities))
	for _, c := range d.Capabilities {
		if KnownCapability(c) && !slices.Contains(caps, c) {
			caps = append(caps, c)
		}
	}
	if len(caps) == 0 {
		return fmt.Errorf("registry: no recognized capabilities requested")
	}
	d.Capabilities = caps

	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[d.ID] = &d
	return r.persistLocked()
}

// Get returns a copy of the device, revoked or not — callers that need
// the distinction check Revoked().
func (r *Registry) Get(id string) (Device, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// List returns every device, paired order not guaranteed.
func (r *Registry) List() []Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Device, 0, len(r.devices))
	for _, d := range r.devices {
		out = append(out, *d)
	}
	return out
}

// Allowed is THE authorization check: the device exists, is not
// revoked, and holds the capability. Every session-surface RPC calls
// this live.
func (r *Registry) Allowed(id, capability string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return ErrNotFound
	}
	if d.Revoked() {
		return ErrRevoked
	}
	if !slices.Contains(d.Capabilities, capability) {
		return fmt.Errorf("registry: device %s lacks %s", id, capability)
	}
	return nil
}

// SetCapabilities replaces a device's grant set (host-side policy UI).
func (r *Registry) SetCapabilities(id string, caps []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return ErrNotFound
	}
	kept := make([]string, 0, len(caps))
	for _, c := range caps {
		if KnownCapability(c) && !slices.Contains(kept, c) {
			kept = append(kept, c)
		}
	}
	d.Capabilities = kept
	return r.persistLocked()
}

// Touch records that the device was heard from. Persisted best-effort:
// losing a LastSeenAt to a crash costs a stale timestamp, nothing more.
func (r *Registry) Touch(id string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.devices[id]; ok {
		d.LastSeenAt = at.UTC()
		_ = r.persistLocked()
	}
}

// Revoke tombstones a device. The caller (the link server) is
// responsible for also dropping its session tokens and cancelling its
// streams — in one process, in the same breath.
func (r *Registry) Revoke(id string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return ErrNotFound
	}
	if !d.Revoked() {
		t := at.UTC()
		d.RevokedAt = &t
	}
	return r.persistLocked()
}

func (r *Registry) persistLocked() error {
	f := registryFile{Version: 1}
	for _, d := range r.devices {
		f.Devices = append(f.Devices, *d)
	}
	slices.SortFunc(f.Devices, func(a, b Device) int {
		return a.PairedAt.Compare(b.PairedAt)
	})
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
