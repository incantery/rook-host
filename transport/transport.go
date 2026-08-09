// Package transport is the TLS front door: an ephemeral-port listener
// presenting the identity's pinned certificate, serving the link
// handler over HTTP/2. It decides nothing — no permissions, no trust,
// no policy; those live above (link) and beside (identity, registry)
// it. Swapping this package for a relay or a WAN dialer must never
// change what a device may do.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/incantery/rook-host/identity"
)

// Listener is a live TLS front door.
type Listener struct {
	srv  *http.Server
	ln   net.Listener
	port int
	done chan error
}

// Listen opens addr (":0" for ephemeral) with the identity's TLS
// credential and serves handler until Shutdown. TLS 1.3 only — every
// client is ours, and the pin ceremony assumes nothing older.
func Listen(addr string, id *identity.Identity, handler http.Handler) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{id.TLSCert},
			MinVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	l := &Listener{
		srv:  srv,
		ln:   ln,
		port: ln.Addr().(*net.TCPAddr).Port,
		done: make(chan error, 1),
	}
	go func() {
		// ServeTLS (rather than Serve on a tls.Listener) so net/http
		// configures HTTP/2 — the stream rail wants h2, and connect
		// clients negotiate it via ALPN.
		err := srv.ServeTLS(ln, "", "")
		if !errors.Is(err, http.ErrServerClosed) {
			l.done <- err
		}
		close(l.done)
	}()
	return l, nil
}

// Port is the bound port — what Bonjour advertises and the QR carries.
func (l *Listener) Port() int { return l.port }

// Err reports a serve failure, if one has happened. Nil while healthy.
func (l *Listener) Err() error {
	select {
	case err := <-l.done:
		return err
	default:
		return nil
	}
}

// Shutdown drains and closes.
func (l *Listener) Shutdown(ctx context.Context) error {
	return l.srv.Shutdown(ctx)
}

// Addrs returns this machine's plausible direct IPv4/IPv6 addresses —
// the QR's connection hints. Best effort: loopback and link-local are
// skipped, and an empty result just means the phone leans on Bonjour.
func Addrs() []string {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range ifaces {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if v4 := ipn.IP.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}
