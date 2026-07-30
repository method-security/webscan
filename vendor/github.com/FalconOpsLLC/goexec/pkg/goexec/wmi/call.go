package wmiexec

import (
  "context"
  "encoding/json"
  "fmt"
  "github.com/rs/zerolog"
  "io"
)

type WmiCall struct {
  Wmi

  Class  string
  Method string
  Args   map[string]any

  Out io.Writer
}

func (m *WmiCall) Call(ctx context.Context) (err error) {
  var outMap map[string]any

  if outMap, err = m.query(ctx, m.Class, m.Method, m.Args); err != nil {
    return
  }
  zerolog.Ctx(ctx).Info().Msg("WMI call successful")

  out, err := json.Marshal(outMap)

  if m.Out != nil {
    // Write output with a trailing line feed
    if _, err = m.Out.Write(append(out, 0x0a)); err != nil {
      return fmt.Errorf("write output: %w", err)
    }
  }
  return
}
