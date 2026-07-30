package dce

import (
  "context"
  "fmt"
  "net"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/RedTeamPentesting/adauth"
  "github.com/RedTeamPentesting/adauth/dcerpcauth"
  "github.com/oiweiwei/go-msrpc/dcerpc"
)

type Options struct {
  goexec.ClientOptions
  goexec.AuthOptions

  // NoSign disables packet signing by omitting dcerpc.WithSign()
  NoSign bool `json:"no_sign" yaml:"no_sign"`

  // NoSeal disables packet stub encryption by omitting dcerpc.WithSeal()
  NoSeal bool `json:"no_seal" yaml:"no_seal"`

  // NoLog disables logging by omitting dcerpc.WithLogger(...)
  NoLog bool `json:"no_log" yaml:"no_log"`

  // UseEpm enables DCE endpoint mapper communications
  UseEpm bool `json:"use_epm" yaml:"use_epm"`

  // NoEpm disables DCE endpoint mapper communications
  NoEpm bool `json:"no_epm" yaml:"no_epm"` // Deprecated in favor of UseEpm

  // Endpoint stores the explicit DCE string binding to use
  Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`

  // Filter stores the filter for returned endpoints from an endpoint mapper
  Filter string `json:"filter,omitempty" yaml:"filter,omitempty"`

  // Smb enables SMB transport for DCE/RPC
  Smb bool `json:"use_smb" yaml:"use_smb"`

  stringBindings []*dcerpc.StringBinding
  dialer         goexec.Dialer
  authOptions    []dcerpc.Option
  DcerpcOptions  []dcerpc.Option
  EpmOptions     []dcerpc.Option
}

func (c *Client) Parse(ctx context.Context) (err error) {

  // Reset internals
  {
    c.dialer = nil
    c.stringBindings = []*dcerpc.StringBinding{}
    c.authOptions = []dcerpc.Option{}
    c.DcerpcOptions = []dcerpc.Option{}
    c.EpmOptions = []dcerpc.Option{
      dcerpc.WithSign(), // Require signing for EPM
    }
  }

  if !c.NoSeal {
    // Enable encryption
    c.DcerpcOptions = append(c.DcerpcOptions, dcerpc.WithSeal(), dcerpc.WithSecurityLevel(dcerpc.AuthLevelPktPrivacy))
    c.EpmOptions = append(c.EpmOptions, dcerpc.WithSeal(), dcerpc.WithSecurityLevel(dcerpc.AuthLevelPktPrivacy))
  }
  if !c.NoSign {
    // Enable signing
    c.DcerpcOptions = append(c.DcerpcOptions, dcerpc.WithSign())
  }

  // Parse DCERPC endpoint
  if c.Endpoint != "" {
    sb, err := dcerpc.ParseStringBinding(c.Endpoint)
    if err != nil {
      return err
    }
    if sb.ProtocolSequence == dcerpc.ProtocolSequenceNamedPipe {
      c.Smb = true
    }
    c.stringBindings = append(c.stringBindings, sb)
  }

  // Parse EPM filter
  if c.Filter != "" {
    sb, err := dcerpc.ParseStringBinding(c.Filter)
    if err != nil {
      return err
    }
    if sb.ProtocolSequence == dcerpc.ProtocolSequenceNamedPipe {
      c.Smb = true
    }
    c.stringBindings = append(c.stringBindings, sb)
  }

  if c.Proxy != "" {
    // Parse proxy URL
    c.dialer, err = goexec.ParseProxyURI(c.Proxy)
    if err != nil {
      return err
    }

    d := adauth.AsContextDialer(c.dialer)
    c.DcerpcOptions = append(c.DcerpcOptions, dcerpc.WithDialer(d))
    c.EpmOptions = append(c.EpmOptions, dcerpc.WithDialer(d))

  } else {
    c.dialer = &net.Dialer{}
  }

  // Parse authentication parameters
  if c.authOptions, err = dcerpcauth.AuthenticationOptions(ctx, c.Credential, c.Target, &dcerpcauth.Options{
    KerberosDialer: c.dialer, // Use the same net dialer as dcerpc
  }); err != nil {
    return fmt.Errorf("parse auth c: %w", err)
  }

  c.Host = c.Target.AddressWithoutPort()

  return
}
