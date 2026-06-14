package request

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

func urlErr(inner error) error {
	return &url.Error{Op: "Get", URL: "https://example.com", Err: inner}
}

func dialErr(inner error) error {
	return urlErr(&net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443},
		Err:  inner,
	})
}

func TestClassifyTransportError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		category TransportErrorCategory
		wantAddr string
	}{
		{name: "connection refused", err: dialErr(os.NewSyscallError("connect", syscall.ECONNREFUSED)), category: TransportErrorConnRefused, wantAddr: "1.2.3.4:443"},
		{name: "connection reset", err: dialErr(os.NewSyscallError("read", syscall.ECONNRESET)), category: TransportErrorConnReset},
		{name: "no route to host", err: dialErr(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), category: TransportErrorNoRouteToHost},
		{name: "network unreachable", err: dialErr(os.NewSyscallError("connect", syscall.ENETUNREACH)), category: TransportErrorNetworkDown},
		{name: "syscall timeout", err: dialErr(os.NewSyscallError("connect", syscall.ETIMEDOUT)), category: TransportErrorTimeout},
		{name: "dns not found", err: urlErr(&net.DNSError{Name: "nope.example.com", IsNotFound: true}), category: TransportErrorDNS, wantAddr: "nope.example.com"},
		{name: "context deadline", err: urlErr(context.DeadlineExceeded), category: TransportErrorTimeout},
		{name: "context canceled", err: urlErr(context.Canceled), category: TransportErrorCanceled},
		{name: "tls unknown authority", err: urlErr(x509.UnknownAuthorityError{}), category: TransportErrorTLS},
		{name: "tls handshake string", err: urlErr(errors.New("tls: handshake failure")), category: TransportErrorTLS},
		{name: "tls-looking url does not override cause", err: &url.Error{Op: "Get", URL: "https://example.com/tls:x509", Err: &net.OpError{
			Op:   "dial",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443},
			Err:  os.NewSyscallError("connect", syscall.ECONNREFUSED),
		}}, category: TransportErrorConnRefused, wantAddr: "1.2.3.4:443"},
		{name: "unknown transport", err: urlErr(errors.New("something weird happened")), category: TransportErrorTransport},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detail := ClassifyTransportError(tt.err)
			if detail.Category != tt.category {
				t.Fatalf("category = %q, want %q (cause=%q)", detail.Category, tt.category, detail.Cause)
			}
			if detail.Cause == "" {
				t.Fatalf("cause must never be empty for %v", tt.err)
			}
			if tt.wantAddr != "" && detail.Address != tt.wantAddr {
				t.Fatalf("address = %q, want %q", detail.Address, tt.wantAddr)
			}
			if detail.String() == "" {
				t.Fatalf("String() must not be empty")
			}
		})
	}
}

func TestClassifyTransportErrorNil(t *testing.T) {
	if got := ClassifyTransportError(nil); got.Category != "" || got.Cause != "" {
		t.Fatalf("nil error should classify to empty detail, got %+v", got)
	}
}

func TestUnwrapURLError(t *testing.T) {
	inner := errors.New("real cause")
	if got := UnwrapURLError(urlErr(inner)); got != inner {
		t.Fatalf("UnwrapURLError = %v, want %v", got, inner)
	}
	if got := UnwrapURLError(inner); got != inner {
		t.Fatalf("non-url error should pass through, got %v", got)
	}
}
