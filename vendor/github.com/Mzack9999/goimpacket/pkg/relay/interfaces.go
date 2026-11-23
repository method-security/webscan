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

package relay

import "net"

// AuthResult carries relayed auth results from server to orchestrator.
type AuthResult struct {
	NTLMType1  []byte   // Raw NTLMSSP Negotiate
	NTLMType3  []byte   // Raw NTLMSSP Authenticate (filled after Type2 relay)
	Username   string   // DOMAIN\user extracted from Type3
	Domain     string   // Domain from Type3
	SourceAddr string   // Victim IP:port
	ServerConn net.Conn // Victim connection (for SOCKS keep-alive)

	// Channels used for the relay handshake between server and orchestrator
	Type2Ch  chan []byte // Orchestrator sends Type2 challenge here
	Type3Ch  chan []byte // Server sends Type3 auth here
	ResultCh chan bool   // Orchestrator signals success/failure
}

// ProtocolServer captures victim authentication.
type ProtocolServer interface {
	Start(resultChan chan<- AuthResult) error
	Stop() error
}

// ProtocolClient relays auth to a target and maintains a session.
type ProtocolClient interface {
	// InitConnection establishes the connection to the target.
	InitConnection() error

	// SendNegotiate relays the NTLM Type1 negotiate and returns the Type2 challenge.
	SendNegotiate(ntlmType1 []byte) (ntlmType2 []byte, err error)

	// SendAuth relays the NTLM Type3 authenticate. Returns nil on success.
	SendAuth(ntlmType3 []byte) error

	// GetSession returns the protocol-specific session object for use by attacks.
	// For SMB this returns the *SMBRelayClient, for LDAP the *ldap.Client, etc.
	GetSession() interface{}

	// KeepAlive sends a heartbeat to prevent session timeout.
	KeepAlive() error

	// Kill terminates the connection.
	Kill()

	// IsAdmin returns true if the relayed session has admin privileges.
	IsAdmin() bool
}

// AttackModule executes post-authentication actions on a relayed session.
type AttackModule interface {
	// Name returns the attack name for display.
	Name() string

	// Run executes the attack using the given session and config.
	// The session type depends on the protocol client that produced it.
	Run(session interface{}, config *Config) error
}
