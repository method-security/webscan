package smb

import (
  "context"
  "errors"
  "fmt"
  "github.com/oiweiwei/go-smb2.fork"
  "github.com/rs/zerolog"
  "net"
)

type Client struct {
  ClientOptions

  conn  net.Conn
  sess  *smb2.Session
  mount *smb2.Share

  connected bool
  share     string
}

func (c *Client) Session() (sess *smb2.Session) {
  return c.sess
}

func (c *Client) String() string {
  return ClientName
}

func (c *Client) Logger(ctx context.Context) zerolog.Logger {
  return zerolog.Ctx(ctx).With().Str("client", c.String()).Logger()
}

func (c *Client) Mount(ctx context.Context, share string) (err error) {

  if c.sess == nil {
    return errors.New("SMB session not initialized")
  }

  c.mount, err = c.sess.Mount(share)
  zerolog.Ctx(ctx).Debug().Str("share", share).Msg("Mounted SMB share")
  c.share = share

  return
}

func (c *Client) Connect(ctx context.Context) (err error) {

  log := c.Logger(ctx)
  {
    if c.netDialer == nil {
      panic(fmt.Errorf("TCP dialer not initialized"))
    }
    if c.dialer == nil {
      panic(fmt.Errorf("%s dialer not initialized", c.String()))
    }
  }

  // Establish TCP connection
  c.conn, err = c.netDialer.Dial("tcp", net.JoinHostPort(c.Host, "445"))

  if err != nil {
    return err
  }

  log = log.With().Str("address", c.conn.RemoteAddr().String()).Logger()
  log.Debug().Msgf("Connected to %s server", c.String())

  // Open SMB session
  c.sess, err = c.dialer.DialContext(ctx, c.conn)

  if err != nil {
    log.Error().Err(err).Msgf("Failed to open %s session", c.String())
    return fmt.Errorf("dial %s: %w", c.String(), err)
  }
  log.Debug().Msgf("Opened %s session", c.String())

  c.connected = true

  return
}

func (c *Client) Close(ctx context.Context) (err error) {

  log := c.Logger(ctx)

  c.connected = false

  // Close SMB session
  if c.sess != nil {
    defer func() {
      if err = c.sess.Logoff(); err != nil {
        log.Debug().Err(err).Msgf("Failed to discard SMB session")
      } else {
        log.Debug().Msg("Discarded SMB session")
      }
    }()

  } else if c.conn != nil {

    defer func() {
      if err = c.conn.Close(); err != nil {
        log.Debug().Err(err).Msgf("Failed to disconnect SMB client")
      } else {
        log.Debug().Msg("Disconnected SMB client")
      }
    }()
  }

  // Unmount SMB share
  if c.mount != nil {
    defer func() {
      if err = c.mount.Umount(); err != nil {
        log.Debug().Err(err).Msg("Failed to unmount share")
      } else {
        log.Debug().Msg("Unmounted file share")
      }
      c.share = ""
    }()
  }
  return
}
