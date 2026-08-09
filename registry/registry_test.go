package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func dev(t *testing.T, name string, caps ...string) Device {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if caps == nil {
		caps = DefaultCapabilities
	}
	return Device{
		ID:           name,
		Name:         name,
		PublicKey:    pub,
		Capabilities: caps,
		PairedAt:     time.Now().UTC(),
	}
}

func TestAddGetPersistReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d := dev(t, "seths-iphone")
	if err := r.Add(d); err != nil {
		t.Fatalf("add: %v", err)
	}

	r2, err := Open(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := r2.Get("seths-iphone")
	if !ok || got.Name != "seths-iphone" || len(got.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("device did not survive reload: %+v %v", got, ok)
	}
	if err := r2.Allowed("seths-iphone", CapStatusRead); err != nil {
		t.Fatalf("allowed after reload: %v", err)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(path, []byte("{ nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt registry silently emptied — that un-pairs every device")
	}
}

func TestAllowedIsTheWholeVerdict(t *testing.T) {
	r, _ := Open(filepath.Join(t.TempDir(), "d.json"))
	if err := r.Add(dev(t, "reader", CapStatusRead)); err != nil {
		t.Fatal(err)
	}

	if err := r.Allowed("reader", CapStatusRead); err != nil {
		t.Fatalf("granted capability refused: %v", err)
	}
	if err := r.Allowed("reader", CapAgentCommand); err == nil {
		t.Fatal("ungranted capability allowed")
	}
	if err := r.Allowed("ghost", CapStatusRead); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown device: %v, want ErrNotFound", err)
	}
}

func TestRevokeIsATombstoneAndRePairIsDeliberate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.json")
	r, _ := Open(path)
	d := dev(t, "lost-phone")
	if err := r.Add(d); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke("lost-phone", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := r.Allowed("lost-phone", CapStatusRead); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked device: %v, want ErrRevoked", err)
	}
	// The tombstone survives a reload — a restart must not resurrect a
	// stolen phone.
	r2, _ := Open(path)
	if err := r2.Allowed("lost-phone", CapStatusRead); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revocation lost across reload: %v", err)
	}
	// Adding the same key again (fresh QR ceremony) replaces the stone.
	if err := r2.Add(d); err != nil {
		t.Fatalf("deliberate re-pair refused: %v", err)
	}
	if err := r2.Allowed("lost-phone", CapStatusRead); err != nil {
		t.Fatalf("re-paired device still refused: %v", err)
	}
}

func TestDuplicateLiveDeviceRefused(t *testing.T) {
	r, _ := Open(filepath.Join(t.TempDir(), "d.json"))
	d := dev(t, "phone")
	if err := r.Add(d); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(d); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second add of a live device: %v, want ErrDuplicate", err)
	}
}

func TestUnknownCapabilitiesAreDropped(t *testing.T) {
	r, _ := Open(filepath.Join(t.TempDir(), "d.json"))
	d := dev(t, "weird", CapStatusRead, "root.everything", CapStatusRead)
	if err := r.Add(d); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get("weird")
	if len(got.Capabilities) != 1 || got.Capabilities[0] != CapStatusRead {
		t.Fatalf("capability set not filtered: %v", got.Capabilities)
	}

	all := dev(t, "nothing", "root.everything")
	if err := r.Add(all); err == nil {
		t.Fatal("device with no recognized capabilities admitted")
	}
}
