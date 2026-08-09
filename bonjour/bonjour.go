// Package bonjour advertises a host's link listener over mDNS —
// `_rook-link._tcp` — in-process, so the advertisement dies with the
// process.
//
// The TXT record is a ROUTING HINT, never identity: a phone matches
// paired hosts by the hid field, then proves the match with the TLS
// pin and the challenge. Anything on the network can advertise
// anything; nothing here is trusted.
//
// Two implementations, chosen at build time:
//
//   - darwin+cgo: DNSServiceRegister against the system's
//     mDNSResponder (dns_sd.h lives in libSystem — no dependency).
//     This is the only registration that RELIABLY answers on macOS:
//     mDNSResponder owns udp/5353, so a pure-Go responder sharing the
//     port via REUSEPORT never sees the queries. The daemon also
//     withdraws the records the moment this process's IPC socket
//     closes — SIGKILL included — which is exactly the lifecycle a
//     plugin needs.
//   - everything else: a pure-Go responder (brutella/dnssd), the only
//     package in the module allowed to import it (the boundary test
//     enforces that, and swapping responders stays a one-package
//     change).
package bonjour

// ServiceType is the Bonjour service this rail advertises and browses.
const ServiceType = "_rook-link._tcp."

// Info is one advertisement.
type Info struct {
	// Name is the instance name — the user-visible host name. mDNS
	// handles conflict renaming.
	Name string
	Port int
	// HostID, TrustDomainID, ProtocolVersion fill the TXT hint.
	HostID          string
	TrustDomainID   string
	ProtocolVersion string
}

func (i Info) txt() map[string]string {
	return map[string]string{
		"v":   "1",
		"hid": i.HostID,
		"td":  i.TrustDomainID,
		"pv":  i.ProtocolVersion,
	}
}
