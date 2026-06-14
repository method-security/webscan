package request

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// TransportErrorCategory is a stable, coarse classification of an HTTP attempt
// that never produced a response. Because there is no HTTP status code in that
// case, this category is the closest thing to an "error code" an operator can
// filter/triage on, which is exactly what is missing when a request fails behind
// a restrictive firewall and the only artifact is an opaque error.
type TransportErrorCategory string

const (
	TransportErrorDNS           TransportErrorCategory = "dns_resolution_failed"
	TransportErrorConnRefused   TransportErrorCategory = "connection_refused"
	TransportErrorConnReset     TransportErrorCategory = "connection_reset"
	TransportErrorTimeout       TransportErrorCategory = "timeout"
	TransportErrorTLS           TransportErrorCategory = "tls_error"
	TransportErrorNoRouteToHost TransportErrorCategory = "no_route_to_host"
	TransportErrorNetworkDown   TransportErrorCategory = "network_unreachable"
	TransportErrorCanceled      TransportErrorCategory = "canceled"
	TransportErrorTransport     TransportErrorCategory = "transport_error"
)

// TransportErrorDetail is a structured, operator-facing description of a failed
// transport attempt. Cause is always the fully unwrapped error string (never the
// reflected struct), and the remaining fields name the layer that failed so a
// firewall/DNS/TLS problem can be told apart at a glance.
type TransportErrorDetail struct {
	Category TransportErrorCategory
	Cause    string
	Op       string
	Network  string
	Address  string
}

// String renders the detail as a single human-readable line suitable for a log
// param, a returned error, or a signal error entry.
func (d TransportErrorDetail) String() string {
	var b strings.Builder
	b.WriteString(string(d.Category))
	if d.Address != "" {
		fmt.Fprintf(&b, " (%s", d.Address)
		if d.Network != "" {
			fmt.Fprintf(&b, "/%s", d.Network)
		}
		b.WriteString(")")
	}
	if d.Cause != "" {
		fmt.Fprintf(&b, ": %s", d.Cause)
	}
	return b.String()
}

// ClassifyTransportError unwraps a Go HTTP client error (typically a *url.Error
// wrapping *net.OpError / *net.DNSError / x509 / tls / syscall errors) into a
// stable category plus the underlying cause and the network layer that failed.
// It exists so that a web request which never reaches the target surfaces *why*
// (DNS, refused, reset, no route, TLS, timeout) instead of an opaque struct dump
// — the common failure shape when egress is blocked by a customer firewall.
func ClassifyTransportError(err error) TransportErrorDetail {
	if err == nil {
		return TransportErrorDetail{}
	}
	causeErr := UnwrapURLError(err)
	detail := TransportErrorDetail{Category: TransportErrorTransport, Cause: causeErr.Error()}

	if opErr := asOpError(err); opErr != nil {
		detail.Op = opErr.Op
		detail.Network = opErr.Net
		if opErr.Addr != nil {
			detail.Address = opErr.Addr.String()
		}
	}

	switch {
	case errors.Is(err, context.Canceled):
		detail.Category = TransportErrorCanceled
	case errors.Is(err, context.DeadlineExceeded):
		detail.Category = TransportErrorTimeout
	case isDNSError(err, &detail):
		detail.Category = TransportErrorDNS
	case isTLSError(causeErr):
		detail.Category = TransportErrorTLS
	case classifySyscall(err, &detail):
		// category set by classifySyscall
	case isTimeout(err):
		detail.Category = TransportErrorTimeout
	}
	return detail
}

func asOpError(err error) *net.OpError {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr
	}
	return nil
}

func isDNSError(err error, detail *TransportErrorDetail) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.Name != "" {
			detail.Address = dnsErr.Name
		}
		return true
	}
	return false
}

func isTLSError(err error) bool {
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostnameErr      x509.HostnameError
		invalidCert      x509.CertificateInvalidError
		certVerifyErr    *tls.CertificateVerificationError
		recordHeaderErr  *tls.RecordHeaderError
	)
	if errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &certVerifyErr) ||
		errors.As(err, &recordHeaderErr) {
		return true
	}
	// TLS alerts and handshake failures are not always typed; fall back to the
	// conventional "tls:" / "x509:" prefixes the stdlib uses.
	msg := err.Error()
	return strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:")
}

func classifySyscall(err error, detail *TransportErrorDetail) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.ECONNREFUSED:
		detail.Category = TransportErrorConnRefused
	case syscall.ECONNRESET, syscall.EPIPE:
		detail.Category = TransportErrorConnReset
	case syscall.EHOSTUNREACH:
		detail.Category = TransportErrorNoRouteToHost
	case syscall.ENETUNREACH, syscall.ENETDOWN:
		detail.Category = TransportErrorNetworkDown
	case syscall.ETIMEDOUT:
		detail.Category = TransportErrorTimeout
	default:
		return false
	}
	return true
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// UnwrapURLError returns the inner error of a *url.Error, which strips the
// repeated `Method "url":` prefix when the caller already logs the URL
// separately. The original error is returned when it is not a *url.Error.
func UnwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}
