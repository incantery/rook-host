// Package identity is what a host IS on the link rail: a durable
// Ed25519 identity key, a trust-domain id, and a TLS keypair for the
// transport. The Ed25519 key is the identity — stable across
// transports, relays, and TLS rotations. The TLS certificate is only a
// transport credential, pinned by fingerprint at pairing time (ECDSA
// P-256 rather than Ed25519 because Apple's TLS stacks do not reliably
// accept Ed25519 server certificates).
//
// The trust-domain id is minted at first boot and stored beside the
// keys rather than derived from them: rotating a key must never rename
// the domain.
package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is a host's long-lived cryptographic material, loaded from
// (or minted into) one state file.
type Identity struct {
	// Key is the Ed25519 identity key. Signatures made with it are the
	// host's word; its public half is what devices learn at pairing.
	Key ed25519.PrivateKey
	// TLSCert is the transport credential the listener presents.
	TLSCert tls.Certificate
	// TrustDomainID is the domain this host belongs to. V1: one host,
	// one domain.
	TrustDomainID string
}

// idEncoding is lowercase unpadded base32: QR-friendly, hostname-safe,
// case-insensitive to read aloud.
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// fingerprint derives the printable id for a public key:
// base32(sha256(pub)[:16]), 26 characters.
func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return strings.ToLower(idEncoding.EncodeToString(sum[:16]))
}

// HostIDFor and DeviceIDFor are the same derivation with different
// names, because the two sides of the wire should never confuse which
// one they are holding.
func HostIDFor(pub ed25519.PublicKey) string   { return fingerprint(pub) }
func DeviceIDFor(pub ed25519.PublicKey) string { return fingerprint(pub) }

// HostID is this identity's printable handle.
func (id *Identity) HostID() string { return HostIDFor(id.PublicKey()) }

// PublicKey is the Ed25519 public half.
func (id *Identity) PublicKey() ed25519.PublicKey {
	return id.Key.Public().(ed25519.PublicKey)
}

// SPKIPin is the base64url SHA-256 of the TLS leaf's SubjectPublicKeyInfo
// — the value the QR carries and the device checks against every
// presented certificate.
func (id *Identity) SPKIPin() (string, error) {
	if len(id.TLSCert.Certificate) == 0 {
		return "", fmt.Errorf("identity: no TLS certificate")
	}
	leaf, err := x509.ParseCertificate(id.TLSCert.Certificate[0])
	if err != nil {
		return "", err
	}
	return PinSPKI(leaf), nil
}

// PinSPKI computes the pin for any parsed certificate — the device
// side of the check uses this same function in tests.
func PinSPKI(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// stateFile is the on-disk shape. The Ed25519 key travels as its seed;
// the TLS pair as PEM. HostID is derivable from the seed and stored
// anyway — denormalized so a sibling process (the cloud bridge, say)
// can learn who this machine is with a JSON read instead of a key
// derivation. The loader never trusts it; it re-derives.
type stateFile struct {
	Version       int       `json:"version"`
	HostID        string    `json:"hostId,omitempty"`
	HostSeed      string    `json:"hostSeed"` // base64 of the 32-byte Ed25519 seed
	TLSCertPEM    string    `json:"tlsCertPem"`
	TLSKeyPEM     string    `json:"tlsKeyPem"`
	TrustDomainID string    `json:"trustDomainId"`
	CreatedAt     time.Time `json:"createdAt"`
}

// LoadOrCreate reads the identity at path, minting and persisting a
// fresh one (0600, parent dirs 0700) if none exists. Any existing file
// that fails to parse is an error, never silently replaced — replacing
// an identity orphans every paired device.
func LoadOrCreate(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return load(raw)
	case os.IsNotExist(err):
		return create(path)
	default:
		return nil, err
	}
}

func load(raw []byte) (*Identity, error) {
	var f stateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("identity: state file is not JSON: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(f.HostSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: host seed is malformed")
	}
	cert, err := tls.X509KeyPair([]byte(f.TLSCertPEM), []byte(f.TLSKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("identity: TLS keypair: %w", err)
	}
	if f.TrustDomainID == "" {
		return nil, fmt.Errorf("identity: state file has no trust domain")
	}
	return &Identity{
		Key:           ed25519.NewKeyFromSeed(seed),
		TLSCert:       cert,
		TrustDomainID: f.TrustDomainID,
	}, nil
}

func create(path string) (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hostID := HostIDFor(priv.Public().(ed25519.PublicKey))

	certPEM, keyPEM, err := selfSignedTLS(hostID)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	domain, err := randomUUID()
	if err != nil {
		return nil, err
	}

	f := stateFile{
		Version:       1,
		HostID:        hostID,
		HostSeed:      base64.StdEncoding.EncodeToString(priv.Seed()),
		TLSCertPEM:    string(certPEM),
		TLSKeyPEM:     string(keyPEM),
		TrustDomainID: domain,
		CreatedAt:     time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Atomic: never leave a half-written identity for the next boot to
	// half-load.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}

	return &Identity{Key: priv, TLSCert: cert, TrustDomainID: domain}, nil
}

// selfSignedTLS mints the transport credential: ECDSA P-256, ten-year
// self-signed certificate with the host id as its common name. Nobody
// verifies a chain against this — devices pin the SPKI — so the long
// validity is honest rather than lazy.
func selfSignedTLS(hostID string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostID},
		DNSNames:              []string{hostID},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// randomUUID is a v4 UUID from crypto/rand — the trust-domain id needs
// uniqueness, not structure.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
