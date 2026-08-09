package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.json")

	id1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id1.HostID() == "" || len(id1.HostID()) != 26 {
		t.Fatalf("host id %q, want 26 chars", id1.HostID())
	}
	if id1.TrustDomainID == "" {
		t.Fatal("no trust domain minted")
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v %v", fi.Mode(), err)
	}

	id2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if id2.HostID() != id1.HostID() {
		t.Fatal("identity changed across a reload")
	}
	if id2.TrustDomainID != id1.TrustDomainID {
		t.Fatal("trust domain changed across a reload — key rotation must never rename the domain, and neither may a restart")
	}
	pin1, _ := id1.SPKIPin()
	pin2, _ := id2.SPKIPin()
	if pin1 == "" || pin1 != pin2 {
		t.Fatalf("SPKI pin unstable: %q vs %q", pin1, pin2)
	}
}

func TestCorruptStateIsAnErrorNotAReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("corrupt identity silently replaced — that orphans every paired device")
	}
}

func TestTLSCertIsPinnableP256(t *testing.T) {
	id, err := LoadOrCreate(filepath.Join(t.TempDir(), "id.json"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(id.TLSCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("TLS leaf is %v, want ECDSA (Apple stacks refuse Ed25519 leaves)", leaf.PublicKeyAlgorithm)
	}
	if leaf.Subject.CommonName != id.HostID() {
		t.Fatalf("leaf CN %q, want host id %q", leaf.Subject.CommonName, id.HostID())
	}
	pin, err := id.SPKIPin()
	if err != nil || pin != PinSPKI(leaf) {
		t.Fatalf("pin mismatch: %q vs %q (%v)", pin, PinSPKI(leaf), err)
	}
}

func TestPairProofBindsHostSecretAndKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	proof := SignPairProof(priv, "host-a", "secret-1", pub)

	if !VerifyPairProof(pub, "host-a", "secret-1", proof) {
		t.Fatal("honest proof refused")
	}
	if VerifyPairProof(pub, "host-b", "secret-1", proof) {
		t.Fatal("proof spendable against a different host")
	}
	if VerifyPairProof(pub, "host-a", "secret-2", proof) {
		t.Fatal("proof spendable with a different secret")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyPairProof(otherPub, "host-a", "secret-1", proof) {
		t.Fatal("proof verified against the wrong key")
	}
	if VerifyPairProof(pub, "host-a", "secret-1", nil) {
		t.Fatal("empty proof accepted")
	}
}

func TestAuthSignatureBindsHostDeviceAndNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nonce := []byte("0123456789abcdef0123456789abcdef")
	sig := SignAuth(priv, "host-a", "dev-1", nonce)

	if !VerifyAuth(pub, "host-a", "dev-1", nonce, sig) {
		t.Fatal("honest signature refused")
	}
	if VerifyAuth(pub, "host-b", "dev-1", nonce, sig) {
		t.Fatal("signature spendable against a different host")
	}
	if VerifyAuth(pub, "host-a", "dev-2", nonce, sig) {
		t.Fatal("signature spendable as a different device")
	}
	if VerifyAuth(pub, "host-a", "dev-1", []byte("different nonce material!!!!!!!!"), sig) {
		t.Fatal("signature spendable with a different nonce")
	}
}

// The length-prefixed canonical encoding must not let one field's
// suffix impersonate its neighbor — the classic concatenation attack.
func TestCanonicalFieldsCannotShift(t *testing.T) {
	a := canonical("d", []byte("ab"), []byte("c"))
	b := canonical("d", []byte("a"), []byte("bc"))
	if string(a) == string(b) {
		t.Fatal("field boundaries ambiguous")
	}
}
