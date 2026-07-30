package wmiexec

import (
  "context"
  "errors"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/rs/zerolog"
)

const (
  MethodProc = "Proc"
)

type WmiProc struct {
  Wmi
  IO               goexec.ExecutionIO
  WorkingDirectory string
}

func (m *WmiProc) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("module", ModuleName).
    Str("method", MethodProc).
    Logger()
  ctx = log.WithContext(ctx)

  if execIO == nil {
    return errors.New("execution IO is nil")
  }

  out, err := m.query(ctx,
    "Win32_Process",
    "Create",
    map[string]any{
      "CommandLine": execIO.String(),
      "WorkingDir":  m.WorkingDirectory,
    },
  )
  if err != nil {
    return
  }

  if pid, ok := out["ProcessId"].(uint32); pid != 0 {
    log = log.With().Uint32("pid", pid).Logger()

  } else if !ok {
    return errors.New("process creation failed")
  }
  log.Info().Err(err).Msg("Process created")

  if ret, ok := out["ReturnValue"].(uint32); ret != 0 {
    log.Error().Err(err).Uint32("return", ret).Msg("Process returned non-zero exit code")

  } else if !ok {
    return errors.New("invalid call response")
  }
  return
}
