package smb

import (
  "context"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "io"
  "os"
  "path"
  "strings"
)

type FileStager struct {
  goexec.Cleaner

  Client *Client

  Share          string
  SharePath      string
  File           string
  relativePath   string
  ForceReconnect bool
  DeleteStage    bool
}

func (o *FileStager) Stage(ctx context.Context, reader io.Reader) (err error) {

  o.relativePath = path.Join(
    strings.ReplaceAll(pathPrefix.ReplaceAllString(o.SharePath, ""), `\`, "/"),
    strings.ReplaceAll(pathPrefix.ReplaceAllString(o.File, ""), `\`, "/"),
  )

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

  writer, err := o.Client.mount.OpenFile(o.relativePath, os.O_WRONLY, 0644)
  if err != nil {
    return fmt.Errorf("open remote file for writing: %w", err)
  }

  if _, err = io.Copy(writer, reader); err != nil {
    return
  }

  o.AddCleaners(func(_ context.Context) error { return writer.Close() })

  if o.DeleteStage {
    o.AddCleaners(func(_ context.Context) error {
      return o.Client.mount.Remove(o.relativePath)
    })
  }

  return
}
