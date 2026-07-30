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

package header

// Auth Constants
const (
	// AuthnLevel
	AuthnLevelNone         = 0
	AuthnLevelConnect      = 2
	AuthnLevelPkt          = 4
	AuthnLevelPktIntegrity = 5
	AuthnLevelPktPrivacy   = 6 // Encryption

	// AuthnSvc
	AuthnWinNT        = 10 // NTLM
	AuthnGSSNegotiate = 9  // SPNEGO
	AuthnKerberos     = 16
	AuthnNetlogon     = 68
)

// SecTrailer is appended to the body if AuthLength > 0.
type SecTrailer struct {
	AuthType  uint8
	AuthLevel uint8
	PadLen    uint8
	Reserved  uint8
	ContextID uint32
}
