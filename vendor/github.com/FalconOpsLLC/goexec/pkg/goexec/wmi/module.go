package wmiexec

import (
  "context"
  "errors"
  "fmt"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/FalconOpsLLC/goexec/pkg/goexec/dce"
  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio/query"
  "github.com/rs/zerolog"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"
)

const (
  ModuleName      = "WMI"
  DefaultEndpoint = "ncacn_ip_tcp:[135]"
)

type Wmi struct {
  goexec.Cleaner
  Client *dce.Client

  Resource string

  servicesClient iwbemservices.ServicesClient
}

func (m *Wmi) Connect(ctx context.Context) (err error) {

  if err = m.Client.Connect(ctx); err == nil {
    m.AddCleaners(m.Client.Close)
  }
  return
}

func (m *Wmi) Init(ctx context.Context) (err error) {

  log := zerolog.Ctx(ctx).With().
    Str("module", ModuleName).Logger()

  if m.Client == nil || m.Client.Dce() == nil {
    return errors.New("DCE connection not initialized")
  }

  actClient, err := iactivation.NewActivationClient(ctx, m.Client.Dce())
  if err != nil {
    log.Error().Err(err).Msg("Failed to initialize IActivation client")
    return fmt.Errorf("create IActivation client: %w", err)
  }

  actResponse, err := actClient.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
    ORPCThis:                   ORPCThis,
    ClassID:                    wmi.Level1LoginClassID.GUID(),
    IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
    RequestedProtocolSequences: []uint16{ProtocolSequenceRPC}, // FEATURE: Named pipe support?
  })
  if err != nil {
    log.Error().Err(err).Msg("Failed to activate remote object")
    return fmt.Errorf("request remote activation: %w", err)
  }
  if actResponse.HResult != 0 {
    return fmt.Errorf("remote activation failed with code %d", actResponse.HResult)
  }

  log.Info().Msg("Remote activation succeeded")

  var newOpts []dcerpc.Option

  for _, bind := range actResponse.OXIDBindings.GetStringBindings() {
    stringBinding, err := dcerpc.ParseStringBinding(bind.String())
    if err != nil {
      log.Debug().Err(err).Msg("Failed to parse string binding")
      continue
    }
    // Only consider ncacn_ip_tcp endpoints
    if stringBinding.ProtocolSequence == dcerpc.ProtocolSequenceIPTCP {
      stringBinding.NetworkAddress = m.Client.Target.AddressWithoutPort()
      newOpts = append(newOpts, dcerpc.WithEndpoint(stringBinding.String()))
    }
  }

  if err = m.Client.Reconnect(ctx, newOpts...); err != nil {
    log.Error().Err(err).Msg("Failed to connect to remote instance")
    return fmt.Errorf("connect remote instance: %w", err)
  }

  log.Info().Msg("Connected to remote instance")

  ipid := actResponse.InterfaceData[0].GetStandardObjectReference().Std.IPID
  loginClient, err := iwbemlevel1login.NewLevel1LoginClient(ctx, m.Client.Dce(), dcom.WithIPID(ipid))

  if err != nil {
    log.Error().Err(err).Msg("Failed to create IWbemLevel1Login client")
    return fmt.Errorf("create IWbemLevel1Login client: %w", err)
  }

  login, err := loginClient.NTLMLogin(ctx, &iwbemlevel1login.NTLMLoginRequest{
    This:            ORPCThis,
    NetworkResource: m.Resource,
  })

  if err != nil {
    log.Error().Err(err).Msg("Failed to login on remote instance")
    return fmt.Errorf("login: IWbemLevel1Login::NTLMLogin: %w", err)
  }

  log.Info().Msg("Completed NTLMLogin operation")

  ipid = login.Namespace.InterfacePointer().IPID()
  m.servicesClient, err = iwbemservices.NewServicesClient(ctx, m.Client.Dce(), dcom.WithIPID(ipid))

  if err != nil {
    log.Error().Err(err).Msg("Failed to create services client")
    return fmt.Errorf("create IWbemServices client: %w", err)
  }

  log.Info().Msg("Initialized services client")

  return
}

func (m *Wmi) query(ctx context.Context, class, method string, values map[string]any) (map[string]any, error) {
  if m.servicesClient == nil {
    return nil, errors.New("module has not been initialized")
  }
  if out, err := query.NewBuilder(ctx, m.servicesClient, ComVersion).
    Spawn(class).   // The class to instantiate (i.e., Win32_Process)
    Method(method). // The method to call (i.e., Create)
    Values(values). // The values to pass to method
    Exec().
    Object(); err == nil {
    return out.Values(), err
  } else {
    return nil, fmt.Errorf("spawn WMI query: %w", err)
  }
}
