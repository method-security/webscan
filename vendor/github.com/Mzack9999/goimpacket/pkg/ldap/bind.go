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
	"fmt"
	"strings"

	"github.com/Mzack9999/goimpacket/pkg/kerberos"
)

// Login attempts to bind to the LDAP server using the session credentials.
// Supports password, NTLM hash, and Kerberos authentication.
func (c *Client) Login() error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	// Check authentication method in priority order
	if c.Session.UseKerberos {
		return c.LoginWithKerberos()
	}

	if c.Session.Hash != "" {
		return c.LoginWithHash()
	}

	// Use password auth
	bindUser := c.Session.Username
	if c.Session.Domain != "" {
		bindUser = fmt.Sprintf("%s\\%s", c.Session.Domain, c.Session.Username)
	}
	return c.LoginWithUser(bindUser)
}

// LoginWithKerberos performs Kerberos GSSAPI SASL bind.
func (c *Client) LoginWithKerberos() error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	// Create Kerberos client from session credentials (uses ccache)
	krbClient, err := kerberos.NewClientFromSession(c.Session, c.Target, c.Session.DCIP)
	if err != nil {
		return fmt.Errorf("failed to create kerberos client: %v", err)
	}

	// Create GSSAPI client wrapper
	gssClient := NewKerberosGSSAPIClient(krbClient)

	// Build SPN for LDAP service
	spn := fmt.Sprintf("ldap/%s", c.Target.Host)

	// Perform GSSAPI bind
	err = c.Conn.GSSAPIBind(gssClient, spn, "")
	if err != nil {
		return fmt.Errorf("GSSAPI bind failed: %v", err)
	}

	return nil
}

// LoginWithHash attempts to bind using NTLM hash authentication.
func (c *Client) LoginWithHash() error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	// Parse the hash - format is LMHASH:NTHASH
	hash := c.Session.Hash
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		if len(parts) == 2 {
			// Use NT hash (second part)
			hash = parts[1]
		}
	}

	domain := c.Session.Domain
	if domain == "" {
		domain = "WORKGROUP"
	}

	err := c.Conn.NTLMBindWithHash(domain, c.Session.Username, hash)
	if err != nil {
		return fmt.Errorf("NTLM bind failed: %v", err)
	}

	return nil
}

// LoginWithUser attempts to bind using a specific username and the session password.
func (c *Client) LoginWithUser(username string) error {
	if c.Conn == nil {
		return fmt.Errorf("connection not established")
	}

	// Check if we have an NTLM hash - if so, use NTLM bind
	if c.Session.Hash != "" {
		return c.LoginWithHash()
	}

	err := c.Conn.Bind(username, c.Session.Password)
	if err != nil {
		return fmt.Errorf("bind failed: %v", err)
	}

	return nil
}
