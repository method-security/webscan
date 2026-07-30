package tschexec

import (
  "context"
  "encoding/xml"
  "errors"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/FalconOpsLLC/goexec/pkg/goexec/dce"
  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/msrpc/tsch/itaskschedulerservice/v1"
  "github.com/rs/zerolog"
  "strings"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  ModuleName = "TSCH"
)

type Tsch struct {
  goexec.Cleaner

  Client *dce.Client
  tsch   itaskschedulerservice.TaskSchedulerServiceClient

  TaskPath  string
  UserSid   string
  NotHidden bool
}

type registerOptions struct {
  AllowStartOnDemand bool
  AllowHardTerminate bool
  StartWhenAvailable bool
  Hidden             bool
  DeleteAfter        string

  triggers taskTriggers
}

func (m *Tsch) Connect(ctx context.Context) (err error) {

  if err = m.Client.Connect(ctx); err == nil {
    m.AddCleaners(m.Client.Close)
  }
  return
}

func (m *Tsch) Init(ctx context.Context) (err error) {

  if m.Client.Dce() == nil {
    return errors.New("DCE connection not initialized")
  }

  // Create ITaskSchedulerService Client
  m.tsch, err = itaskschedulerservice.NewTaskSchedulerServiceClient(ctx, m.Client.Dce(), dcerpc.WithSeal())
  return
}

func (m *Tsch) registerTask(ctx context.Context, opts *registerOptions, in *goexec.ExecutionIO) (path string, err error) {

  log := zerolog.Ctx(ctx).With().
    Str("task", m.TaskPath).
    Logger()

  ctx = log.WithContext(ctx)

  principalId := "LocalSystem"

  settings := taskSettings{
    MultipleInstancesPolicy: "IgnoreNew",
    IdleSettings: taskIdleSettings{
      StopOnIdleEnd: true,
      RestartOnIdle: false,
    },
    Enabled:                true,
    Priority:               7, // a pretty standard value for scheduled tasks
    AllowHardTerminate:     opts.AllowHardTerminate,
    AllowStartOnDemand:     opts.AllowStartOnDemand,
    Hidden:                 opts.Hidden,
    StartWhenAvailable:     opts.StartWhenAvailable,
    DeleteExpiredTaskAfter: opts.DeleteAfter,
  }

  principals := taskPrincipals{
    Principals: []taskPrincipal{
      {
        ID:       principalId,
        UserID:   m.UserSid,
        RunLevel: "HighestAvailable",
      },
    }}

  var cmd, args string

  cmdline := in.CommandLine()

  if l := len(cmdline); l >= 1 {
    cmd = cmdline[0]
    if l >= 2 {
      args = strings.Join(cmdline[1:], " ")
    }
  }

  actions := taskActions{
    Context: principalId,
    Exec: []taskActionExec{
      {
        Command:   cmd,
        Arguments: args,
      },
    },
  }

  def := simpleTask{
    TaskVersion:   TaskXmlVersion,
    TaskNamespace: TaskXmlNamespace,
    Triggers:      opts.triggers,
    Actions:       actions,
    Principals:    principals,
    Settings:      settings,
  }

  // Generate task XML content. See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/0d6383e4-de92-43e7-b0bb-a60cfa36379f

  doc, err := xml.Marshal(def)

  if err != nil {
    log.Error().Err(err).Msg("failed to marshal task XML")
    return "", fmt.Errorf("marshal task: %w", err)
  }

  taskXml := TaskXmlHeader + string(doc)

  log.Debug().Str("content", taskXml).Msg("Generated task XML")

  registerResponse, err := m.tsch.RegisterTask(ctx, &itaskschedulerservice.RegisterTaskRequest{
    Path:       m.TaskPath,
    XML:        taskXml,
    Flags:      0, // FEATURE: dynamic
    SDDL:       "",
    LogonType:  0, // FEATURE: dynamic
    CredsCount: 0,
    Creds:      nil,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to register task")
    return "", fmt.Errorf("register task: %w", err)
  }
  log.Info().Msg("Scheduled task registered")

  return registerResponse.ActualPath, nil
}

func (m *Tsch) deleteTask(ctx context.Context, taskPath string) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("path", taskPath).Logger()

  _, err = m.tsch.Delete(ctx, &itaskschedulerservice.DeleteRequest{
    Path: taskPath,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to delete task")
    return fmt.Errorf("delete task: %w", err)
  }

  log.Info().Msg("Task deleted")

  return
}
