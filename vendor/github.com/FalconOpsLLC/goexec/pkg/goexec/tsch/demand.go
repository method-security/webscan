package tschexec

import (
  "context"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/msrpc/tsch/itaskschedulerservice/v1"
  "github.com/rs/zerolog"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  MethodDemand = "Demand"
)

type TschDemand struct {
  Tsch
  goexec.Executor
  goexec.Cleaner

  IO goexec.ExecutionIO

  NoDelete  bool
  NoStart   bool
  SessionId uint32
}

func (m *TschDemand) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("module", ModuleName).
    Str("method", MethodDemand).
    Str("task", m.TaskPath).
    Logger()

  path, err := m.registerTask(ctx,
    &registerOptions{
      AllowStartOnDemand: true,
      AllowHardTerminate: true,
      Hidden:             !m.NotHidden,
      triggers:           taskTriggers{},
    },
    execIO,
  )
  if err != nil {
    return err
  }

  log.Info().Msg("Task registered")

  if !m.NoDelete {
    m.AddCleaners(func(ctxInner context.Context) error {
      return m.deleteTask(ctxInner, path)
    })
  }

  if !m.NoStart {

    var flags uint32
    if m.SessionId != 0 {
      flags |= 4
    }

    runResponse, err := m.tsch.Run(ctx, &itaskschedulerservice.RunRequest{
      Path:      path,
      Flags:     flags,
      SessionID: m.SessionId,
    })

    if err != nil {
      log.Error().Err(err).Msg("Failed to run task")
      return fmt.Errorf("run task: %w", err)
    }
    if ret := uint32(runResponse.Return); ret != 0 {
      log.Error().Str("code", fmt.Sprintf("0x%08x", ret)).Msg("Task returned non-zero exit code")
      return fmt.Errorf("task returned non-zero exit code: 0x%08x", ret)
    }

    log.Info().Msg("Task started successfully")
  }
  return
}
