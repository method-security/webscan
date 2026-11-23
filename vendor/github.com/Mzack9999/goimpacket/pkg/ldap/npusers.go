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

// UserNP represents a user who might not require pre-authentication.
type UserNP struct {
	Username string
	DN       string
}

// FindNPUsers searches for users with the UF_DONT_REQUIRE_PREAUTH flag (0x400000) set.
func (c *Client) FindNPUsers(baseDN string) ([]UserNP, error) {
	// Filter for users where (userAccountControl & 4194304) is true
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{"sAMAccountName", "distinguishedName"}

	results, err := c.Search(baseDN, filter, attributes)
	if err != nil {
		return nil, err
	}

	var users []UserNP
	for _, entry := range results.Entries {
		users = append(users, UserNP{
			Username: entry.GetAttributeValue("sAMAccountName"),
			DN:       entry.GetAttributeValue("distinguishedName"),
		})
	}
	return users, nil
}
