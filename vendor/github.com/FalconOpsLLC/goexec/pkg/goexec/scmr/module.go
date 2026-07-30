package scmrexec

import (
  "context"
  "errors"
  "fmt"
  "github.com/FalconOpsLLC/goexec/internal/util"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/FalconOpsLLC/goexec/pkg/goexec/dce"
  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
  "github.com/rs/zerolog"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

type Scmr struct {
  goexec.Cleaner

  Client *dce.Client
  ctl    svcctl.SvcctlClient
  scm    *svcctl.Handle

  hostname string
}

const (
  ModuleName = "SCMR"

  DefaultEndpoint = "ncacn_np:[svcctl]"
  ScmrUuid        = "367ABB81-9844-35F1-AD32-98F038001003"
)

func (m *Scmr) Connect(ctx context.Context) (err error) {

  if err = m.Client.Connect(ctx); err == nil {
    m.AddCleaners(m.Client.Close)
  }
  return
}

func (m *Scmr) Init(ctx context.Context) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("module", ModuleName).Logger()

  if m.Client == nil || m.Client.Dce() == nil {
    return errors.New("DCE connection not initialized")
  }

  m.hostname, err = m.Client.Target.Hostname(ctx)
  if err != nil {
    log.Debug().Err(err).Msg("Failed to determine target hostname")
  }
  if m.hostname == "" {
    m.hostname = util.RandomHostname()
  }

  svcctlOpts := []dcerpc.Option{dcerpc.WithObjectUUID(uuid.MustParse(ScmrUuid))}

  if m.Client.Smb {
    svcctlOpts = append(svcctlOpts, dcerpc.WithInsecure())
  }

  m.ctl, err = svcctl.NewSvcctlClient(ctx, m.Client.Dce(), svcctlOpts...)
  if err != nil {
    log.Error().Err(err).Msg("Failed to initialize SVCCTL client")
    return fmt.Errorf("create SVCCTL client: %w", err)
  }
  log.Info().Msg("Created SVCCTL client")

  resp, err := m.ctl.OpenSCMW(ctx, &svcctl.OpenSCMWRequest{
    MachineName:   m.hostname,
    DatabaseName:  "ServicesActive",
    DesiredAccess: ServiceAllAccess,
  })
  if err != nil {
    log.Debug().Err(err).Msg("Failed to open SCM handle")
    return fmt.Errorf("open SCM handle: %w", err)
  }
  log.Info().Msg("Opened SCM handle")

  m.scm = resp.SCM

  return
}

func (m *Scmr) Reconnect(ctx context.Context) (err error) {

  if err = m.Client.Reconnect(ctx); err != nil {
    return fmt.Errorf("reconnect: %w", err)
  }
  if err = m.Init(ctx); err != nil {
    return fmt.Errorf("reconnect SCMR: %w", err)
  }
  return
}

// openService will a handle to the desired service
func (m *Scmr) openService(ctx context.Context, name string) (svc *service, err error) {

  log := zerolog.Ctx(ctx)

  resp, err := m.ctl.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
    ServiceManager: m.scm,
    ServiceName:    name,
    DesiredAccess:  ServiceAllAccess, // TODO: dynamic
  })
  if err != nil {
    log.Error().Err(err).Msg("Failed to open service handle")
    return nil, fmt.Errorf("open service: %w", err)
  }

  log.Info().Msg("Opened service handle")

  svc = new(service)
  svc.name = name
  svc.handle = resp.Service

  return
}

func (m *Scmr) startService(ctx context.Context, svc *service) error {

  log := zerolog.Ctx(ctx).With().
    Str("service", svc.name).Logger()

  sr, err := m.ctl.StartServiceW(ctx, &svcctl.StartServiceWRequest{Service: svc.handle})

  if err != nil {

    if errors.Is(err, context.DeadlineExceeded) { // Check if execution timed out (execute "cmd.exe /c notepad" for test case)
      log.Warn().Msg("Service execution deadline exceeded")
      svc.handle = nil
      return nil

    } else if sr.Return == ErrorServiceRequestTimeout {
      log.Info().Msg("Received request timeout. Execution was likely successful")
      return nil
    }

    log.Error().Err(err).Msg("Failed to start service")
    return fmt.Errorf("start service: %w", err)
  }
  log.Info().Msg("Service started successfully")
  return nil
}

func (m *Scmr) deleteService(ctx context.Context, svc *service) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("service", svc.name).Logger()

  deleteResponse, err := m.ctl.DeleteService(ctx, &svcctl.DeleteServiceRequest{
    Service: svc.handle,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to delete service")
    return fmt.Errorf("delete service: %w", err)
  }

  if deleteResponse.Return != 0 {
    log.Error().Err(err).Str("code", fmt.Sprintf("0x%02x", deleteResponse.Return)).Msg("Failed to delete service")
    return fmt.Errorf("delete service returned non-zero exit code: 0x%02x", deleteResponse.Return)
  }

  log.Info().Msg("Deleted service")
  return
}

func (m *Scmr) closeService(ctx context.Context, svc *service) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("service", svc.name).Logger()

  closResponse, err := m.ctl.CloseService(ctx, &svcctl.CloseServiceRequest{
    ServiceObject: svc.handle,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to close service handle")
    return fmt.Errorf("close service: %w", err)
  }

  if closResponse.Return != 0 {
    log.Error().Err(err).Str("code", fmt.Sprintf("0x%02x", closResponse.Return)).Msg("Failed to close service handle")
    return fmt.Errorf("close service returned non-zero exit code: 0x%02x", closResponse.Return)
  }

  log.Info().Msg("Closed service handle")
  return
}
