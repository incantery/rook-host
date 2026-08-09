// The link rail's two signed statements, in edgesign's canonical
// style: domain label, then each field length-prefixed, in order. The
// encoding can only change by changing the label.
//
// Both signatures bind the HOST id even though the device signs:
// a proof or challenge answer minted for one host must never be
// spendable against another.

package identity

import (
	"crypto/ed25519"
	"encoding/binary"
)

const (
	pairDomain = "rook-link-pair/v1"
	authDomain = "rook-link-auth/v1"
)

// SignPairProof is the device's enrollment statement: possession of
// the device key, bound to this host and this pairing secret.
func SignPairProof(devKey ed25519.PrivateKey, hostID, pairingSecret string, devPub ed25519.PublicKey) []byte {
	return ed25519.Sign(devKey, pairBytes(hostID, pairingSecret, devPub))
}

// VerifyPairProof is the host's check of that statement.
func VerifyPairProof(devPub ed25519.PublicKey, hostID, pairingSecret string, proof []byte) bool {
	return len(proof) > 0 && ed25519.Verify(devPub, pairBytes(hostID, pairingSecret, devPub), proof)
}

// SignAuth answers a connection challenge: the device key over the
// host, the device, and the single-use nonce.
func SignAuth(devKey ed25519.PrivateKey, hostID, deviceID string, nonce []byte) []byte {
	return ed25519.Sign(devKey, authBytes(hostID, deviceID, nonce))
}

// VerifyAuth is the host's check of a challenge answer.
func VerifyAuth(devPub ed25519.PublicKey, hostID, deviceID string, nonce, sig []byte) bool {
	return len(sig) > 0 && ed25519.Verify(devPub, authBytes(hostID, deviceID, nonce), sig)
}

func pairBytes(hostID, secret string, devPub ed25519.PublicKey) []byte {
	return canonical(pairDomain, []byte(hostID), []byte(secret), devPub)
}

func authBytes(hostID, deviceID string, nonce []byte) []byte {
	return canonical(authDomain, []byte(hostID), []byte(deviceID), nonce)
}

// canonical mirrors edgesign's encoding exactly: length prefixes make
// the concatenation unambiguous — no field can impersonate its
// neighbor's suffix.
func canonical(domain string, fields ...[]byte) []byte {
	out := make([]byte, 0, 64+len(fields)*16)
	out = append(out, u64(uint64(len(domain)))...)
	out = append(out, domain...)
	for _, f := range fields {
		out = append(out, u64(uint64(len(f)))...)
		out = append(out, f...)
	}
	return out
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
