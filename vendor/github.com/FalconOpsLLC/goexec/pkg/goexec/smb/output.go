package smb

import (
  "context"
  "errors"
  "io"
  "os"
  "path/filepath"
  "regexp"
  "strings"
  "time"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/rs/zerolog"
)

var (
  DefaultOutputPollInterval = 500 * time.Millisecond
  DefaultOutputPollTimeout  = 60 * time.Second
  pathPrefix                = regexp.MustCompile(`^([a-zA-Z]:)?[\\/]*`)
)

type OutputFileFetcher struct {
  goexec.Cleaner

  Client *Client

  Share            string
  SharePath        string
  File             string
  DeleteOutputFile bool
  ForceReconnect   bool

  relativePath string
}

func (o *OutputFileFetcher) GetOutput(ctx context.Context, writer io.Writer) (err error) {
  log := zerolog.Ctx(ctx)
  timeout := DefaultOutputPollTimeout
  pollInterval := DefaultOutputPollInterval

  if v := ctx.Value(goexec.ContextOptionOutputTimeout); v != nil {
    if t, ok := v.(time.Duration); ok {
      timeout = t
    }
  }
  if v := ctx.Value(goexec.ContextOptionOutputPollInterval); v != nil {
    if p, ok := v.(time.Duration); ok {
      pollInterval = p
    }
  }
  shp := pathPrefix.ReplaceAllString(strings.ToLower(strings.ReplaceAll(o.SharePath, `\`, "/")), "")
  fp := pathPrefix.ReplaceAllString(strings.ToLower(strings.ReplaceAll(o.File, `\`, "/")), "")

  if o.relativePath, err = filepath.Rel(shp, fp); err != nil {
    return
  }

  log.Info().Str("path", o.relativePath).Msg("Fetching output file")

  if o.ForceReconnect || !o.Client.connected {
    err = o.Client.Connect(ctx)
    if err != nil {
      return
    }
    defer o.AddCleaners(o.Client.Close)
  }

  if o.ForceReconnect || o.Client.share != o.Share {
    err = o.Client.Mount(ctx, o.Share)
    if err != nil {
      return
    }
  }

  if reader, err := func() (io.ReadCloser, error) {
    timer := time.NewTimer(timeout)
    defer timer.Stop()
    poll := time.NewTicker(pollInterval)
    defer poll.Stop()

    for {
      select {
      case <-ctx.Done():
        return nil, ctx.Err()
      case <-timer.C:
        return nil, errors.New("execution output timeout")
      case <-poll.C:
        // Open the remote file as RW; otherwise the output may be returned before the remote process exits
        reader, err := o.Client.mount.OpenFile(o.relativePath, os.O_RDWR, 0)
        if err == nil {
          return reader, nil // success
        }
      }
    }
  }(); err != nil {
    return err
  } else {
    o.AddCleaners(func(_ context.Context) error {
      return reader.Close()
    })
    if _, err := io.Copy(writer, reader); err != nil {
      if o.DeleteOutputFile {
        o.AddCleaners(func(_ context.Context) error {
          return o.Client.mount.Remove(o.relativePath)
        })
      }
    }
  }

  return
}
