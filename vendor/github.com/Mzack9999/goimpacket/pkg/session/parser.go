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
	"strconv"
	"strings"
)

// ParseTargetString parses a string in the format [domain/]user[:password]@target[:port]
func ParseTargetString(input string) (Target, Credentials, error) {
	var target Target
	var creds Credentials

	// Split on the LAST @ to handle passwords containing @
	lastAt := strings.LastIndex(input, "@")
	if lastAt == -1 {
		return target, creds, fmt.Errorf("invalid format: missing '@'")
	}

	authPart := input[:lastAt]
	targetPart := input[lastAt+1:]

	// Handle target host and port
	if strings.Contains(targetPart, ":") {
		tParts := strings.SplitN(targetPart, ":", 2)
		target.Host = tParts[0]
		p, err := strconv.Atoi(tParts[1])
		if err == nil {
			target.Port = p
		}
	} else {
		target.Host = targetPart
		target.Port = 0 // Tool will set default
	}

	// Handle domain/user and password
	authSplit := strings.SplitN(authPart, ":", 2)
	userPart := authSplit[0]
	if len(authSplit) == 2 {
		creds.Password = authSplit[1]
	}

	if strings.Contains(userPart, "/") {
		userSplit := strings.SplitN(userPart, "/", 2)
		creds.Domain = userSplit[0]
		creds.Username = userSplit[1]
	} else {
		creds.Username = userPart
	}

	return target, creds, nil
}
