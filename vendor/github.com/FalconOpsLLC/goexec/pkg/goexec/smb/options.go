package smb

import (
  "context"
  "errors"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/RedTeamPentesting/adauth/smbauth"
  msrpcSMB2 "github.com/oiweiwei/go-msrpc/smb2"
  "github.com/oiweiwei/go-smb2.fork"
  "net"
)

var supportedDialects = map[msrpcSMB2.Dialect]msrpcSMB2.Dialect{
  2_0_2: msrpcSMB2.SMB202,
  2_1_0: msrpcSMB2.SMB210,
  3_0_0: msrpcSMB2.SMB300,
  3_0_2: msrpcSMB2.SMB302,
  3_1_1: msrpcSMB2.SMB311,

  0x202: msrpcSMB2.SMB202,
  0x210: msrpcSMB2.SMB210,
  0x300: msrpcSMB2.SMB300,
  0x302: msrpcSMB2.SMB302,
  0x311: msrpcSMB2.SMB311,
}

// ClientOptions holds configuration settings for an SMB client
type ClientOptions struct {
  goexec.ClientOptions
  goexec.AuthOptions

  // NoSign disables packet signing
  NoSign bool `json:"no_sign" yaml:"no_sign"`

  // NoSeal disables packet encryption
  NoSeal bool `json:"no_seal" yaml:"no_seal"`

  // Dialect sets the SMB dialect to be passed to smb2.WithDialect()
  Dialect msrpcSMB2.Dialect `json:"dialect" yaml:"dialect"`

  netDialer goexec.Dialer
  dialer    *smb2.Dialer
}

func (c *Client) Parse(ctx context.Context) (err error) {

  var do []msrpcSMB2.DialerOption

  if c.Dialect != 0 { // Use specific dialect

    // Validate SMB dialect/version
    if d, ok := supportedDialects[c.Dialect]; ok {
      do = append(do, msrpcSMB2.WithDialect(d))

    } else {
      return errors.New("unsupported SMB version")
    }
  }

  if c.Proxy == "" {
    c.netDialer = &net.Dialer{}

  } else {
    // Parse proxy URL
    c.netDialer, err = goexec.ParseProxyURI(c.Proxy)
    if err != nil {
      return err
    }
  }

  if !c.NoSeal {
    // Enable encryption
    do = append(do, msrpcSMB2.WithSeal())
  }
  if !c.NoSign {
    // Enable signing
    do = append(do, msrpcSMB2.WithSign())
  }

  // Validate authentication parameters
  c.dialer, err = smbauth.Dialer(ctx, c.Credential, c.Target,
    &smbauth.Options{
      KerberosDialer: c.netDialer,
      SMBOptions:     do,
    })

  if err != nil {
    return fmt.Errorf("set %s auth: %w", ClientName, err)
  }

  c.Host = c.Target.AddressWithoutPort()

  return nil
}
