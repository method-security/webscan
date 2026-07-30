package dce

import (
  "context"
  "fmt"

  "github.com/RedTeamPentesting/adauth/smbauth"
  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
  msrpcSMB2 "github.com/oiweiwei/go-msrpc/smb2"
  "github.com/rs/zerolog"
)

type Client struct {
  Options

  conn dcerpc.Conn
}

func (c *Client) String() string {
  return ClientName
}

func (c *Client) Reconnect(ctx context.Context, opts ...dcerpc.Option) (err error) {
  c.DcerpcOptions = append(c.DcerpcOptions, opts...)

  return c.Connect(ctx)
}

func (c *Client) Dce() (dce dcerpc.Conn) {
  return c.conn
}

func (c *Client) Logger(ctx context.Context) (log zerolog.Logger) {
  return zerolog.Ctx(ctx).With().
    Str("client", c.String()).Logger()
}

func (c *Client) Connect(ctx context.Context) (err error) {

  log := c.Logger(ctx)
  ctx = log.WithContext(ctx)

  var do, eo []dcerpc.Option

  do = append(do, c.DcerpcOptions...)
  do = append(do, c.authOptions...)

  if c.Smb {
    var so []msrpcSMB2.DialerOption

    if !c.NoSign {
      so = append(so, msrpcSMB2.WithSign())
      eo = append(eo, dcerpc.WithSign())
    }
    if !c.NoSeal {
      so = append(so, msrpcSMB2.WithSeal())
      eo = append(eo, dcerpc.WithSeal())
    }

    if smbDialer, err := smbauth.Dialer(ctx, c.Credential, c.Target, &smbauth.Options{
      SMBOptions:     so,
      KerberosDialer: c.dialer,
    }); err != nil {
      return fmt.Errorf("parse smb auth: %w", err)

    } else {
      do = append(do, dcerpc.WithSMBDialer(smbDialer))
    }
  } else {

    if !c.NoSign {
      do = append(do, dcerpc.WithSign())
      eo = append(eo, dcerpc.WithSign())
    }
    if !c.NoSeal {
      do = append(do, dcerpc.WithSeal())
      eo = append(eo, dcerpc.WithSeal())
    }
  }

  if !c.NoLog {
    do = append(do, dcerpc.WithLogger(log))
    eo = append(eo, dcerpc.WithLogger(log))
  }

  if c.UseEpm && !c.NoEpm {
    log.Debug().Msg("Using endpoint mapper")

    eo = append(eo, c.EpmOptions...)
    eo = append(eo, c.authOptions...)

    do = append(do, epm.EndpointMapper(ctx, c.Host, eo...))
  }

  for _, e := range c.stringBindings {
    do = append(do, dcerpc.WithEndpoint(e.String()))
  }

  if c.conn, err = dcerpc.Dial(ctx, c.Host, do...); err != nil {

    log.Error().Err(err).Msgf("Failed to connect to %s endpoint", c.String())
    return fmt.Errorf("dial %s: %w", c.String(), err)
  }

  return
}

func (c *Client) Close(ctx context.Context) (err error) {
  return c.conn.Close(ctx)
}
