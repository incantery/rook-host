//go:build darwin && cgo

package bonjour

/*
#include <dns_sd.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

// Advertiser is one registration held open with mDNSResponder. Stop
// (or process death, however abrupt) withdraws it.
type Advertiser struct {
	ref    C.DNSServiceRef
	cancel context.CancelFunc
}

// Advertise registers the service with the system daemon.
func Advertise(ctx context.Context, info Info) (*Advertiser, error) {
	txt, err := txtRecord(info.txt())
	if err != nil {
		return nil, fmt.Errorf("bonjour: %w", err)
	}

	cName := C.CString(info.Name)
	defer C.free(unsafe.Pointer(cName))
	// The C API takes the bare type, no trailing dot domain.
	cType := C.CString("_rook-link._tcp")
	defer C.free(unsafe.Pointer(cType))

	var ref C.DNSServiceRef
	// Port travels in network byte order. No callback: registration
	// errors surface in the return code, and name conflicts are
	// auto-renamed by the daemon (the flag to refuse that is not set).
	nbo := C.uint16_t(((info.Port & 0xff) << 8) | ((info.Port >> 8) & 0xff))
	rc := C.DNSServiceRegister(&ref, 0, 0, cName, cType, nil, nil, nbo,
		C.uint16_t(len(txt)), unsafe.Pointer(&txt[0]), nil, nil)
	if rc != C.kDNSServiceErr_NoError {
		return nil, fmt.Errorf("bonjour: DNSServiceRegister: %d", int(rc))
	}

	ctx, cancel := context.WithCancel(ctx)
	a := &Advertiser{ref: ref, cancel: cancel}
	go func() {
		<-ctx.Done()
		C.DNSServiceRefDeallocate(ref)
	}()
	return a, nil
}

// Stop withdraws the advertisement.
func (a *Advertiser) Stop() { a.cancel() }

// txtRecord encodes key=value pairs in the DNS TXT wire form: one
// length byte, then that many bytes of "key=value".
func txtRecord(kv map[string]string) ([]byte, error) {
	// Deterministic order keeps two hosts with equal hints byte-equal.
	keys := []string{"v", "hid", "td", "pv"}
	var out []byte
	for _, k := range keys {
		entry := k + "=" + kv[k]
		if len(entry) > 255 {
			return nil, fmt.Errorf("TXT entry %q exceeds 255 bytes", k)
		}
		out = append(out, byte(len(entry)))
		out = append(out, entry...)
	}
	return out, nil
}
