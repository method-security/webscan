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
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/Mzack9999/goimpacket/pkg/session"
	"github.com/Mzack9999/goimpacket/pkg/transport"
)

// Client wraps the underlying LDAP connection to provide a unified interface.
type Client struct {
	Conn    *goldap.Conn
	Target  session.Target
	Session *session.Credentials
	dialer  *transport.Dialer
}

// NewClient creates a new LDAP client instance.
func NewClient(target session.Target, creds *session.Credentials) *Client {
	return &Client{
		Target:  target,
		Session: creds,
		dialer:  &transport.Dialer{},
	}
}

// Close terminates the LDAP connection.
func (c *Client) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}
