# 3. QR pairing, pinned TLS, and signed-challenge sessions

Date: 2026-08-09

## Status

Accepted

## Context

Rook Link connects a personal phone to a host machine directly — no
cloud in the path. That requires answering four questions with four
mechanisms, never letting one stand in for another:

1. **What hosts are reachable?** Bonjour (`_rook-link._tcp`). Purely a
   routing hint; anything on the network can advertise anything.
2. **Is this the host I paired with?** A TLS pin. The host serves a
   self-signed ECDSA P-256 certificate; the QR code carries the SHA-256
   of its SPKI, and the phone verifies the presented leaf against that
   pin on every connection. (P-256 rather than Ed25519 for the TLS leaf
   because Apple's TLS stacks do not reliably accept Ed25519 server
   certificates; the host's *identity* remains an Ed25519 key, and the
   TLS keypair is only a transport credential.)
3. **Is this a device I paired?** An Ed25519 signed challenge. Pairing
   registers the device's public key (delivered inside a QR-gated,
   pin-verified TLS session, with a proof signature binding the key to
   this host and this pairing secret). Every connection thereafter:
   server nonce out (32 bytes, single-use, 60s), signature back over
   `canonical("rook-link-auth/v1", host_id, device_id, nonce)`, session
   token issued (~24h, held in host memory).
4. **May this device do that?** A capability check on every RPC
   (`status.read`, `agent.answer`, `agent.command`), read live from the
   device registry — the session token is a handle, not an authority,
   which is what makes revocation instantaneous.

The canonical encoding is edgesign's: domain label, then each field
length-prefixed in order. A change to what is signed is a new domain
label, never a silent reinterpretation.

## Alternatives rejected

- **Long-lived bearer token** minted at pairing: a stolen host state
  file would contain presentable credentials; with signed challenge the
  host stores only public keys. And a bearer is transport-agnostic in
  the wrong way — it proves nothing about key possession when the link
  later runs over a relay.
- **Mutual TLS**: welds device identity to the transport layer — the
  exact coupling the future WAN/relay path cannot have — and iOS
  client-certificate plumbing is the worst-supported corner of the
  Apple stack.
- **Timestamp-based signatures** instead of server nonces: buys one
  fewer RPC per connect at the price of a clock-skew policy and a
  replay window. Connects happen on app foreground; the extra RPC is
  free.

## Consequences

- The QR is needed exactly once per (phone, host). Reconnection is
  Bonjour-by-host-id + pin check + challenge — no rescanning.
- Revocation from the host takes effect on the revoked device's next
  RPC and terminates its open streams; nothing has to expire.
- The same device keypair authenticates over any future transport
  (direct WAN, relay) without protocol change — the signed challenge
  never references the connection.
- The QR URL (`rook-link://pair?...`) carries: version, host_id, trust
  domain, host name, SPKI pin, one-time secret (16 bytes, 120s TTL),
  port, and direct address hints. Everything in it is base64url/base32/
  digits — shell-safe and QR-alphanumeric-friendly by construction.
