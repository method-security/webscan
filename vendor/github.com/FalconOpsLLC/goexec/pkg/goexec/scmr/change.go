package scmrexec

import (
  "context"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
  "github.com/rs/zerolog"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  MethodChange = "Change"
)

type ScmrChange struct {
  Scmr
  goexec.Cleaner
  goexec.Executor

  IO goexec.ExecutionIO

  NoStart     bool
  NoRevert    bool
  ServiceName string
}

func (m *ScmrChange) Execute(ctx context.Context, in *goexec.ExecutionIO) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("service", m.ServiceName).
    Logger()

  svc := &service{name: m.ServiceName}

  openResponse, err := m.ctl.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
    ServiceManager: m.scm,
    ServiceName:    svc.name,
    DesiredAccess:  ServiceAllAccess,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to open service handle")
    return fmt.Errorf("open service request: %w", err)
  }
  if openResponse.Return != 0 {
    log.Error().Err(err).Msg("Failed to open service handle")
    return fmt.Errorf("create service: %w", err)
  }

  svc.handle = openResponse.Service
  log.Info().Msg("Opened service handle")

  defer m.AddCleaners(func(ctxInner context.Context) error {
    return m.closeService(ctxInner, svc)
  })

  // Note the original service configuration
  queryResponse, err := m.ctl.QueryServiceConfigW(ctx, &svcctl.QueryServiceConfigWRequest{
    Service:      svc.handle,
    BufferLength: 8 * 1024,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to fetch service configuration")
    return fmt.Errorf("get service config: %w", err)
  }

  log.Info().Str("binaryPath", queryResponse.ServiceConfig.BinaryPathName).Msg("Fetched original service configuration")
  svc.originalConfig = queryResponse.ServiceConfig

  stopResponse, err := m.ctl.ControlService(ctx, &svcctl.ControlServiceRequest{
    Service: svc.handle,
    Control: ServiceControlStop,
  })

  if err != nil {
    if stopResponse == nil || stopResponse.Return != ErrorServiceNotActive {

      log.Error().Err(err).Msg("Failed to stop existing service")
      return fmt.Errorf("stop service: %w", err)
    }

    log.Debug().Msg("Service is not running")

    // FEATURE: restore state
    /*
       defer m.AddCleaners(func(ctxInner context.Context) error {
         // ...
         return nil
       })
    */

  } else {
    log.Info().Msg("Stopped existing service")
  }

  req := &svcctl.ChangeServiceConfigWRequest{
    Service:          svc.handle,
    BinaryPathName:   in.String(),
    DisplayName:      svc.originalConfig.DisplayName,
    ServiceType:      svc.originalConfig.ServiceType,
    StartType:        ServiceDemandStart,
    ErrorControl:     svc.originalConfig.ErrorControl,
    LoadOrderGroup:   svc.originalConfig.LoadOrderGroup,
    ServiceStartName: svc.originalConfig.ServiceStartName,
    TagID:            svc.originalConfig.TagID,
    Dependencies:     parseDependencies(svc.originalConfig.Dependencies),
  }

  bpn := svc.originalConfig.BinaryPathName

  _, err = m.ctl.ChangeServiceConfigW(ctx, req)

  if err != nil {
    log.Error().Err(err).Msg("Failed to request service configuration change")
    return fmt.Errorf("change service config request: %w", err)
  }

  if !m.NoStart {
    err = m.startService(ctx, svc)
    if err != nil {
      log.Error().Err(err).Msg("Failed to start service")
    }
  }

  if !m.NoRevert {
    if svc.handle == nil {

      if err = m.Reconnect(ctx); err != nil {
        return err
      }
      svc, err = m.openService(ctx, svc.name)

      if err != nil {
        log.Error().Err(err).Msg("Failed to reopen service handle")
        return fmt.Errorf("reopen service: %w", err)
      }
    }
    req.BinaryPathName = bpn
    req.Service = svc.handle
    _, err := m.ctl.ChangeServiceConfigW(ctx, req)

    if err != nil {
      log.Error().Err(err).Msg("Failed to restore original service configuration")
      return fmt.Errorf("restore service config: %w", err)
    }
    log.Info().Msg("Restored original service configuration")
  }

  return
}
