package tschexec

import (
  "context"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/rs/zerolog"
  "time"
)

const (
  MethodCreate = "Create"
)

type TschCreate struct {
  Tsch
  goexec.Executor
  goexec.Cleaner

  IO goexec.ExecutionIO

  NoDelete    bool
  CallDelete  bool
  StartDelay  time.Duration
  StopDelay   time.Duration
  DeleteDelay time.Duration
  TimeOffset  time.Duration
  // FEATURE: more opts
}

func (m *TschCreate) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("module", ModuleName).
    Str("method", MethodCreate).
    Str("task", m.TaskPath).
    Logger()

  startTime := time.Now().UTC().Add(m.StartDelay)
  stopTime := startTime.Add(m.StopDelay)

  trigger := taskTimeTrigger{
    StartBoundary: startTime.Format(TaskXmlDurationFormat),
    Enabled:       true,
  }

  var deleteAfter string

  if !m.NoDelete && !m.CallDelete {

    if m.StopDelay == 0 {
      m.StopDelay = time.Second // value is required, 1 second by default
    }
    trigger.EndBoundary = stopTime.Format(TaskXmlDurationFormat)
    deleteAfter = xmlDuration(m.DeleteDelay)
  }

  path, err := m.registerTask(ctx,
    &registerOptions{
      AllowStartOnDemand: true,
      AllowHardTerminate: true,
      Hidden:             !m.NotHidden,
      triggers: taskTriggers{
        TimeTriggers: []taskTimeTrigger{trigger},
      },
      DeleteAfter: deleteAfter,
    },
    execIO,
  )
  if err != nil {
    return err
  }

  if !m.NoDelete {
    if m.CallDelete {

      m.AddCleaners(func(ctxInner context.Context) error {

        log.Info().Msg("Waiting for task to start...")

        select {
        case <-ctxInner.Done():
          log.Warn().Msg("Task deletion cancelled")

        case <-time.After(m.StartDelay + (5 * time.Second)): // 5 second buffer
          /*
             for {
               stat, err := m.tsch.GetLastRunInfo(ctx, &itaskschedulerservice.GetLastRunInfoRequest{
                 Path: path,
               })
               if err != nil {
                 log.Warn().Err(err).Msg("Failed to get last run info. Assuming task was executed")

               } else if stat.LastRuntime.AsTime().IsZero() {
                 log.Warn().Msg("Task was not yet executed. Waiting 5 additional seconds")

                 time.Sleep(5 * time.Second)
                 continue
               }
               break
             }
          */
        }
        return m.deleteTask(ctxInner, path)
      })

    } else {
      log.Info().Time("when", stopTime).Msg("Task is scheduled to delete")
    }
  }
  return
}
