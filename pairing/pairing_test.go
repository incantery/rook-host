package pairing

import (
	"strings"
	"testing"
	"time"
)

func TestWindowSingleUse(t *testing.T) {
	var m Manager
	now := time.Now()
	s, err := m.Open(now)
	if err != nil {
		t.Fatal(err)
	}
	if !m.OpenNow(now) {
		t.Fatal("window not open after Open")
	}
	if m.Redeem("wrong-secret", now) {
		t.Fatal("wrong secret redeemed")
	}
	if !m.Redeem(s, now) {
		t.Fatal("honest secret refused")
	}
	if m.Redeem(s, now) {
		t.Fatal("secret redeemed twice")
	}
	if m.OpenNow(now) {
		t.Fatal("window still open after redemption")
	}
}

func TestWindowExpires(t *testing.T) {
	var m Manager
	now := time.Now()
	s, _ := m.Open(now)
	late := now.Add(TTL + time.Second)
	if m.OpenNow(late) {
		t.Fatal("window open past TTL")
	}
	if m.Redeem(s, late) {
		t.Fatal("expired secret redeemed")
	}
}

func TestReopenReplacesWindow(t *testing.T) {
	var m Manager
	now := time.Now()
	s1, _ := m.Open(now)
	s2, _ := m.Open(now)
	if m.Redeem(s1, now) {
		t.Fatal("stale window's secret redeemed — two QRs in the world")
	}
	if !m.Redeem(s2, now) {
		t.Fatal("current window's secret refused")
	}
}

func TestQRRoundTrip(t *testing.T) {
	q := QR{
		HostID:        "abcdefghijklmnopqrstuvwxyz",
		TrustDomainID: "0e5e0b1c-8a4e-4b7e-9d7e-000000000000",
		HostName:      "Seth's MacBook Pro",
		SPKIPin:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Secret:        "c2VjcmV0LXNlY3JldA",
		Port:          54321,
		Addrs:         []string{"192.168.1.10", "10.0.0.4"},
	}
	u := q.URL()
	if !strings.HasPrefix(u, "rook-link://pair?") {
		t.Fatalf("url shape: %s", u)
	}
	// Shell-safety by construction: the only quoting-relevant bytes a
	// composed URL may contain are the %-escapes url.Values emits.
	for _, c := range []string{`'`, `"`, "`", ";", "|", " ", "$"} {
		if strings.Contains(u, c) {
			t.Fatalf("url contains shell-relevant byte %q: %s", c, u)
		}
	}
	got, err := ParseURL(u)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostID != q.HostID || got.HostName != q.HostName || got.SPKIPin != q.SPKIPin ||
		got.Secret != q.Secret || got.Port != q.Port || len(got.Addrs) != 2 || got.Addrs[1] != "10.0.0.4" ||
		got.TrustDomainID != q.TrustDomainID {
		t.Fatalf("round trip lost fields: %+v", got)
	}
}

func TestParseRefusesForeignURLs(t *testing.T) {
	for _, bad := range []string{
		"https://evil.example/pair?v=1&hid=x&spki=y&s=z&p=1",
		"rook-link://pair?v=2&hid=x&spki=y&s=z&p=1",
		"rook-link://pair?v=1&spki=y&s=z&p=1",       // no hid
		"rook-link://pair?v=1&hid=x&s=z&p=1",        // no pin
		"rook-link://pair?v=1&hid=x&spki=y&p=1",     // no secret
		"rook-link://pair?v=1&hid=x&spki=y&s=z",     // no port
		"rook-link://pair?v=1&hid=x&spki=y&s=z&p=0", // bad port
	} {
		if _, err := ParseURL(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
