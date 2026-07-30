package goexec

import (
  "github.com/RedTeamPentesting/adauth"
)

// AuthOptions holds Windows / Active Directory authentication parameters
type AuthOptions struct {
  Target     *adauth.Target
  Credential *adauth.Credential
}
