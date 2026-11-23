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

package ldap

import (
	"crypto/tls"
	"fmt"
	"net"

	goldap "github.com/go-ldap/ldap/v3"
)

// Connect establishes the TCP connection to the LDAP server.
// If useTLS is true and port is 636, uses implicit TLS (LDAPS).
// If useTLS is true and port is 389, uses STARTTLS to upgrade.
func (c *Client) Connect(useTLS bool) error {
	// Set default port if 0
	if c.Target.Port == 0 {
		if useTLS {
			c.Target.Port = 636
		} else {
			c.Target.Port = 389
		}
	}

	address := c.Target.Addr()

	// Establish the raw TCP connection using our proxy-aware dialer
	rawConn, err := c.dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	if useTLS && c.Target.Port == 636 {
		// LDAPS: implicit TLS - wrap connection in TLS before LDAP
		tlsConn := tls.Client(rawConn.(net.Conn), tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return fmt.Errorf("TLS handshake failed: %v", err)
		}
		c.Conn = goldap.NewConn(tlsConn, true)
		c.Conn.Start()
	} else if useTLS {
		// STARTTLS: connect plain, then upgrade
		c.Conn = goldap.NewConn(rawConn, false)
		c.Conn.Start()
		if err := c.Conn.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %v", err)
		}
	} else {
		// Plain LDAP
		c.Conn = goldap.NewConn(rawConn, false)
		c.Conn.Start()
	}

	return nil
}
