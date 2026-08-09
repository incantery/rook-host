package transport_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	linkv1 "github.com/incantery/rook-host/gen/rook/link/v1"
	"github.com/incantery/rook-host/gen/rook/link/v1/linkv1connect"
	"github.com/incantery/rook-host/identity"
	"github.com/incantery/rook-host/link"
	"github.com/incantery/rook-host/projection"
	"github.com/incantery/rook-host/registry"
	"github.com/incantery/rook-host/transport"
)

type nopExec struct{}

func (nopExec) Answer(context.Context, projection.Answer) link.Outcome {
	return link.Outcome{Disposition: link.Dropped}
}
func (nopExec) Execute(context.Context, projection.Command) link.Outcome {
	return link.Outcome{Disposition: link.Dropped}
}

// pinnedClient trusts exactly one SPKI — the device's posture. No CA,
// no chain, no hostname: the pin is the whole verdict, which is why a
// wrong pin must fail even against a certificate that would otherwise
// be fine.
func pinnedClient(pin string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // the pin below is the verification
				MinVersion:         tls.VersionTLS13,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return errors.New("no certificate presented")
					}
					leaf, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
					if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != pin {
						return fmt.Errorf("SPKI pin mismatch: presented %s", got)
					}
					return nil
				},
			},
		},
	}
}

func TestTLSListenerWithPinnedClient(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.LoadOrCreate(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := link.NewServer(link.Options{
		Identity: id, Registry: reg, Executor: nopExec{}, HostName: "tls host",
	})

	l, err := transport.Listen(":0", id, srv.Handler())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = l.Shutdown(ctx)
	}()
	if l.Port() == 0 {
		t.Fatal("no ephemeral port bound")
	}
	url := fmt.Sprintf("https://127.0.0.1:%d", l.Port())

	pin, err := id.SPKIPin()
	if err != nil {
		t.Fatal(err)
	}

	// The honest pin connects and speaks.
	host := linkv1connect.NewHostServiceClient(pinnedClient(pin), url)
	info, err := host.GetHostInfo(context.Background(), connect.NewRequest(&linkv1.GetHostInfoRequest{}))
	if err != nil {
		t.Fatalf("pinned GetHostInfo: %v", err)
	}
	if info.Msg.HostId != id.HostID() {
		t.Fatalf("host id %q, want %q", info.Msg.HostId, id.HostID())
	}

	// A wrong pin refuses the connection outright — reachability is not
	// identity, and a reachable impostor gets a handshake failure, not
	// a request.
	wrongPin := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	impostor := linkv1connect.NewHostServiceClient(pinnedClient(wrongPin), url)
	if _, err := impostor.GetHostInfo(context.Background(), connect.NewRequest(&linkv1.GetHostInfoRequest{})); err == nil {
		t.Fatal("wrong pin connected anyway")
	}
}
