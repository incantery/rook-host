//go:build !(darwin && cgo)

package bonjour

import (
	"context"
	"fmt"

	"github.com/brutella/dnssd"
)

// Advertiser is one running advertisement, answered by an in-process
// pure-Go responder.
type Advertiser struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Advertise starts answering for the service until Stop (or ctx ends).
func Advertise(ctx context.Context, info Info) (*Advertiser, error) {
	cfg := dnssd.Config{
		Name: info.Name,
		Type: ServiceType,
		Text: info.txt(),
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
