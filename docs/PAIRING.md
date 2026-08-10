# Pairing and connecting to a Rook Host

The client-side contract for rook.link.v1 — everything a device
implementation (the iOS app, a test client) needs beyond the proto
file. The protocol rationale lives in
`docs/adr/0003-qr-pairing-pinned-tls.md`.

## The QR URL

```
rook-link://pair?v=1
  &hid=<host id, 26 chars lowercase base32>
  &spki=<base64url( sha256( TLS leaf SubjectPublicKeyInfo DER ) )>
  &s=<base64url 16-byte one-time secret; 120s TTL, single use>
  &p=<listener port>
  &a=<comma-joined direct IPv4 hints, optional>
  &td=<trust domain id, optional>
  &n=<host display name, %-encoded, optional>
```

Reject anything whose scheme is not `rook-link`, host not `pair`, or
`v` not `1`. `hid`, `spki`, `s`, and a valid `p` are required.

`td` and `n` are hints a host MAY include; hosts keep the URL minimal
because every byte is QR modules. The authoritative sources are the
`PairResponse` (`trust_domain_id`) and a post-pin `GetHostInfo`
(`host_name`) — prefer those whenever present, and expect the QR to
carry neither.

## Connecting (every connection, forever)

1. **Find the host.** Try the cached last-known address, then the QR's
   `a` hints (first pairing), then browse Bonjour `_rook-link._tcp`
   and match the TXT record's `hid` against the paired host id. TXT is
   a routing hint only — matching it proves nothing.
2. **Open TLS 1.3** to `https://<addr>:<port>`. In the trust callback
   (URLSession `didReceive challenge` / `sec_protocol_verify_block`),
   compute `sha256(leaf SubjectPublicKeyInfo DER)`, base64url, and
   compare to the stored pin. **The pin is the entire verdict**: no CA
   evaluation, no hostname check, and a mismatch is a hard failure —
   never a dialog.

Pseudocode for the trust callback:

```swift
func urlSession(_ s: URLSession, didReceive ch: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard ch.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = ch.protectionSpace.serverTrust,
          let leaf = SecTrustCopyCertificateChain(trust).flatMap({ ($0 as! [SecCertificate]).first }),
          let spki = publicKeyInfoDER(of: leaf)   // SPKI DER, e.g. via SecCertificateCopyKey + header
    else { return completionHandler(.cancelAuthenticationChallenge, nil) }

    let pin = Data(SHA256.hash(data: spki)).base64URLEncodedString()
    if pin == storedPin {
        completionHandler(.useCredential, URLCredential(trust: trust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

## Pairing (once per phone × host)

1. Scan the QR while the host's pairing window is open.
2. Mint the device identity if none exists: Curve25519/Ed25519 signing
   key (CryptoKit `Curve25519.Signing.PrivateKey`), private half in
   the Keychain. This one key identifies the device to EVERY host.
3. Connect as above, pinning the QR's `spki`.
4. Call `HostService.Pair` with:
   - `protocol_version`: `"rook-link/1"`
   - `pairing_secret`: the QR's `s`, verbatim
   - `device_public_key`: 32 raw bytes
   - `proof`: Ed25519 signature over the **canonical pair encoding**
     (below)
5. Persist from the response: `device_id`, `host_id`,
   `trust_domain_id`, `host_public_key`, the granted capabilities —
   alongside the pin and last-known address.

## Authenticating (per connection)

1. `HostService.Challenge(device_id)` → 32-byte nonce (single-use, 60s).
2. `HostService.Authenticate(device_id, nonce, signature)` where the
   signature is Ed25519 over the **canonical auth encoding** (below).
3. Hold the returned `session_token` (~24h) and send it on every
   LinkService call as:

```
Authorization: Bearer link-<token bytes as UTF-8>
```

The token is opaque and lives in host memory: any `unauthenticated`
error means "re-run challenge/authenticate", and a
`permission_denied` on Challenge means the device was revoked — stop
reconnecting and surface un-pairing to the user.

## Canonical signed encodings

Both signatures cover the same length-prefixed layout `edgesign` uses:

```
u64be(len(domain)) || domain || ( u64be(len(field)) || field )*
```

Pair proof — domain `rook-link-pair/v1`, fields in order:

```
host_id (UTF-8) | pairing_secret (UTF-8) | device_public_key (32 raw bytes)
```

Auth signature — domain `rook-link-auth/v1`, fields in order:

```
host_id (UTF-8) | device_id (UTF-8) | nonce (32 raw bytes)
```

`u64be` is an 8-byte big-endian length. Binding `host_id` into both is
what makes a proof or challenge answer minted for one host unspendable
against another.

## Watching status

`LinkService.WatchStatus` (server stream): the first frame is always a
`KIND_SNAPSHOT` of current truth — render it and discard any state
from before the connection. Then: further snapshots (latest wins;
drop any frame whose `seq` is not greater than the last rendered) and
`KIND_HEARTBEAT` frames to ignore. On disconnect, reconnect and rely
on the opening snapshot; there is no gap replay to ask for.

## Watching a pane

`LinkService.WatchPane(session_id)` (server stream) carries a
session's live terminal as display-ready cell grids — direct link
only, per `docs/adr/0004-pane-streaming-direct-only.md`. The contract
mirrors WatchStatus with two differences worth coding for:

- There may be NO opening frame: a session whose pane the host cannot
  resolve right now keeps the stream open on `KIND_HEARTBEAT` alone,
  and frames start when the pane appears. A gap is not an error.
- `seq` is per watched session and restarts when the session loses its
  last watcher — reset your horizon per stream, exactly like the
  reconnect rule for WatchStatus.

Frames are viewport snapshots (no scrollback, no deltas): rows carry
the full text plus style runs of final `0xRRGGBB` color (the host's
emulator already resolved palette, inverse, and faint) and an attrs
bitmask (1 bold, 2 italic, 4 underline, 16 strikethrough). Render
cells; parse nothing.

The stream needs the `session.read` capability. Devices paired before
it existed do not gain it retroactively — re-pairing through a fresh
QR is the upgrade path, and a `permission_denied` close on WatchPane
(with Challenge still succeeding) is how that state looks on the wire.

## Submitting actions

- Prefer the link rail whenever connected; fall back to the cloud rail
  only when the host is unreachable. Never submit the same action on
  both — the host's journal dedupes, but the discipline keeps
  `DISPOSITION_DUPLICATE` an anomaly signal instead of noise.
- `DUPLICATE` is success (the first submission won). `DROPPED` carries
  a human-readable `note` — show it.
- Command field rules (mirrors the host's validation): `compact` and
  `resume` take `session_id` only; `spawn` takes `workspace` and an
  optional `prompt`. Anything else is refused with `invalid_argument`.
