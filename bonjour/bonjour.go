// Package bonjour advertises a host's link listener over mDNS —
// `_rook-link._tcp`, in-process, so the advertisement dies with the
// process (a plugin's exit is SIGKILL; a subprocess responder would
// keep answering for a ghost).
//
// The TXT record is a ROUTING HINT, never identity: a phone matches
// paired hosts by the hid field, then proves the match with the TLS
// pin and the challenge. Anything on the network can advertise
// anything; nothing here is trusted.
//
// This is the only package in the module allowed to import the mDNS
// dependency — the boundary test enforces it, and swapping responders
// stays a one-package change.
package bonjour

import (
	"context"
	"fmt"

	"github.com/brutella/dnssd"
)

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

// Advertiser is one running advertisement.
type Advertiser struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Advertise starts answering for the service until Stop (or ctx ends).
func Advertise(ctx context.Context, info Info) (*Advertiser, error) {
	cfg := dnssd.Config{
		Name: info.Name,
		Type: ServiceType,
		Text: map[string]string{
			"v":   "1",
			"hid": info.HostID,
			"td":  info.TrustDomainID,
			"pv":  info.ProtocolVersion,
		},
		Port: info.Port,
	}
	sv, err := dnssd.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("bonjour: %w", err)
	}
	rp, err := dnssd.NewResponder()
	if err != nil {
		return nil, fmt.Errorf("bonjour: %w", err)
	}
	if _, err := rp.Add(sv); err != nil {
		return nil, fmt.Errorf("bonjour: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &Advertiser{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		// Respond blocks until ctx ends; its error at shutdown is the
		// context's, not news.
		_ = rp.Respond(ctx)
	}()
	return a, nil
}

// Stop withdraws the advertisement and waits for the responder to end.
func (a *Advertiser) Stop() {
	a.cancel()
	<-a.done
}
