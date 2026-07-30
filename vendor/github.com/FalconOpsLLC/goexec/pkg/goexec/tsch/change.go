package tschexec

import (
  "context"
  "encoding/xml"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/FalconOpsLLC/goexec/pkg/goexec/tsch/task"
  "github.com/oiweiwei/go-msrpc/msrpc/tsch/itaskschedulerservice/v1"
  "github.com/rs/zerolog"
  "regexp"
  "time"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  FlagTaskUpdate  uint32 = 0b_00000000_00000000_00000000_00000100
  MethodChange           = "Change"
  DefaultWaitTime        = 1 * time.Second
)

type TschChange struct {
  Tsch
  goexec.Executor
  goexec.Cleaner

  IO goexec.ExecutionIO

  WorkingDirectory string
  NoStart          bool
  NoRevert         bool
  WaitTime         time.Duration
}

func (m *TschChange) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("module", ModuleName).
    Str("method", MethodChange).
    Str("task", m.TaskPath).
    Logger()

  retrieveResponse, err := m.tsch.RetrieveTask(ctx, &itaskschedulerservice.RetrieveTaskRequest{
    Path: m.TaskPath,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to retrieve task")
    return fmt.Errorf("retrieve task: %w", err)
  }
  if retrieveResponse.Return != 0 {
    log.Error().Err(err).Str("code", fmt.Sprintf("0x%02x", retrieveResponse.Return)).
      Msg("Failed to retrieve task")
    return fmt.Errorf("retrieve task returned non-zero exit code: %02x", retrieveResponse.Return)
  }

  log.Info().Msg("Successfully retrieved existing task definition")
  log.Debug().Str("xml", retrieveResponse.XML).Msg("Got task definition")

  tk := task.Task{}

  enc := regexp.MustCompile(`(?i)^<\?xml .*?\?>`)
  tkStr := enc.ReplaceAllString(retrieveResponse.XML, `<?xml version="1.0" encoding="utf-8"?>`)

  if err = xml.Unmarshal([]byte(tkStr), &tk); err != nil {
    log.Error().Err(err).Msg("Failed to unmarshal task XML")

    return fmt.Errorf("unmarshal task XML: %w", err)
  }

  cmd := execIO.CommandLine()

  tk.Actions.Exec = append(tk.Actions.Exec, task.ExecAction{
    Command:          cmd[0],
    Arguments:        cmd[1],
    WorkingDirectory: m.WorkingDirectory,
  })

  doc, err := xml.Marshal(tk)

  if err != nil {
    log.Error().Err(err).Msg("failed to marshal task XML")
    return fmt.Errorf("marshal task: %w", err)
  }

  taskXml := TaskXmlHeader + string(doc)
  log.Debug().Str("xml", taskXml).Msg("Serialized new task")

  registerResponse, err := m.tsch.RegisterTask(ctx, &itaskschedulerservice.RegisterTaskRequest{
    Path:  m.TaskPath,
    XML:   taskXml,
    Flags: FlagTaskUpdate,
  })

  if !m.NoRevert {

    m.AddCleaners(func(ctxInner context.Context) error {

      revertResponse, err := m.tsch.RegisterTask(ctx, &itaskschedulerservice.RegisterTaskRequest{
        Path:  m.TaskPath,
        XML:   retrieveResponse.XML,
        Flags: FlagTaskUpdate,
      })

      if err != nil {
        return err
      }
      if revertResponse.Return != 0 {
        return fmt.Errorf("revert task definition returned non-zero exit code: %02x", revertResponse.Return)
      }
      return nil
    })
  }

  if err != nil {
    log.Error().Err(err).Msg("Failed to update task")

    return fmt.Errorf("update task: %w", err)
  }
  if registerResponse.Return != 0 {
    log.Error().Err(err).Str("code", fmt.Sprintf("0x%02x", registerResponse.Return)).Msg("Failed to update task definition")

    return fmt.Errorf("update task returned non-zero exit code: %02x", registerResponse.Return)
  }
  log.Info().Msg("Successfully updated task definition")

  if !m.NoStart {

    runResponse, err := m.tsch.Run(ctx, &itaskschedulerservice.RunRequest{
      Path: m.TaskPath,
    })

    if err != nil {
      log.Error().Err(err).Msg("Failed to run modified task")

      return fmt.Errorf("run task: %w", err)
    }

    if ret := uint32(runResponse.Return); ret != 0 {
      log.Error().Str("code", fmt.Sprintf("0x%08x", ret)).Msg("Run task returned non-zero exit code")

      return fmt.Errorf("run task returned non-zero exit code: 0x%08x", ret)
    }

    log.Info().Msg("Successfully started modified task")
  }

  if m.WaitTime <= 0 {
    m.WaitTime = DefaultWaitTime
  }
  time.Sleep(m.WaitTime)
  return
}
