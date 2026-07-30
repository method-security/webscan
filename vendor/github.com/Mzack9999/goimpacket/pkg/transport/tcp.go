// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package transport provides a small TCP/TLS dialer used across goimpacket.
//
// The default dialer is a pure-Go net.Dialer (no CGO). Embedders that need
// to route connections through their own stack (custom resolver, proxy chain,
// network policy) can install a DialFunc via SetDial - the override is
// honored by all goimpacket subsystems that go through this package.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is the default connect timeout in seconds.
const DefaultTimeout = 30

// DialFunc is the signature accepted by SetDial.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

var (
	dialMu       sync.RWMutex
	dialOverride DialFunc
)

// SetDial installs a custom dialer used by Dial/DialTimeout/DialTLS.
// Pass nil to reset to the standard net.Dialer.
func SetDial(fn DialFunc) {
	dialMu.Lock()
	dialOverride = fn
	dialMu.Unlock()
}

func currentDial() DialFunc {
	dialMu.RLock()
	defer dialMu.RUnlock()
	return dialOverride
}

// Dial connects to the address on the named network.
// The address must be in "host:port" format.
func Dial(network, address string) (net.Conn, error) {
	return DialTimeout(network, address, DefaultTimeout)
}

// DialContext connects using the supplied context. The context's deadline
// supersedes the default timeout. The package-level DialFunc registered with
// SetDial is honored if installed; otherwise the standard net.Dialer is used.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if _, _, err := splitHostPort(address); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d := currentDial(); d != nil {
		return d(ctx, network, address)
	}
	var dlr net.Dialer
	return dlr.DialContext(ctx, network, address)
}

// DialTimeout connects with the given timeout in seconds.
func DialTimeout(network, address string, timeoutSec int) (net.Conn, error) {
	ctx := context.Background()
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}
	return DialContext(ctx, network, address)
}

// DialTLS connects then wraps the connection in TLS.
func DialTLS(network, address string, config *tls.Config) (*tls.Conn, error) {
	rawConn, err := Dial(network, address)
	if err != nil {
		return nil, err
	}
	host, _, _ := splitHostPort(address)
	if config.ServerName == "" {
		config = config.Clone()
		config.ServerName = host
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// Dialer provides a way to establish connections. When DialFn is set it is
// used for every Dial/DialContext on this Dialer instance, bypassing the
// package-level SetDial override and the stdlib fallback. Embedders should
// install a DialFn closure that captures any per-call state (e.g. an execution
// id) needed to route the connection through their preferred transport.
type Dialer struct {
	TimeoutSec int
	DialFn     DialFunc
}

// Dial establishes a TCP connection to the specified address.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	timeout := d.TimeoutSec
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}
	return d.DialContext(ctx, network, address)
}

// DialContext establishes a TCP connection honoring the context. Per-instance
// DialFn takes precedence over the package-level SetDial hook.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if _, _, err := splitHostPort(address); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d != nil && d.DialFn != nil {
		return d.DialFn(ctx, network, address)
	}
	return DialContext(ctx, network, address)
}

func splitHostPort(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		if !strings.Contains(address, ":") {
			return address, "", fmt.Errorf("missing port in address: %s", address)
		}
		return "", "", fmt.Errorf("invalid address %q: %w", address, err)
	}
	return host, port, nil
}
