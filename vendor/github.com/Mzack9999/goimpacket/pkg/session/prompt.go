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

package session

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
)

// EnsurePassword prompts for a password if one is not present and other auth methods are not used.
func EnsurePassword(creds *Credentials) error {
	if creds.Password != "" || creds.Hash != "" {
		return nil
	}

	if creds.UseKerberos && os.Getenv("KRB5CCNAME") != "" {
		return nil
	}

	fmt.Printf("Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Newline
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	creds.Password = string(bytePassword)
	return nil
}
