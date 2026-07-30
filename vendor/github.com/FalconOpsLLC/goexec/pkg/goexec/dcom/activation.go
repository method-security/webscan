package dcomexec

import (
  "context"
  "fmt"

  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/iremotescmactivator/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dtyp"
  "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  OptRemoteCreateInstance = "RemoteCreateInstance"
  OptRemoteActivation     = "RemoteActivation"
)

// remoteCreateInstance creates a new instance of a COM class on a remote machine using RemoteCreateInstance (opnum 4).
func (m *Dcom) remoteCreateInstance(ctx context.Context, conn dcerpc.Conn, cls *uuid.UUID, iid *dcom.IID) (opts []dcerpc.Option, err error) {
  if cls == nil {
    return nil, fmt.Errorf("class ID is nil")
  }
  ap := &dcom.ActivationProperties{
    DestinationContext: 2,
    Properties: []dcom.ActivationProperty{
      &dcom.InstantiationInfoData{
        ClassID:          (*dcom.ClassID)(dtyp.GUIDFromUUID(cls)),
        IID:              []*dcom.IID{iid},
        ClientCOMVersion: m.comVersion,
      },
      &dcom.ActivationContextInfoData{},
      &dcom.LocationInfoData{},
      &dcom.SCMRequestInfoData{
        RemoteRequest: &dcom.CustomRemoteRequestSCMInfo{
          RequestedProtocolSequences: []uint16{7, 15}, // ncacn_ip_tcp, ncacn_np
        },
      },
    },
  }
  apin, err := ap.ActivationPropertiesIn()
  if err != nil {
    return nil, err
  }
  act, err := iremotescmactivator.NewRemoteSCMActivatorClient(ctx, conn)
  if err != nil {
    return nil, err
  }
  cr, err := act.RemoteCreateInstance(ctx, &iremotescmactivator.RemoteCreateInstanceRequest{
    ORPCThis:        &dcom.ORPCThis{Version: m.comVersion},
    ActPropertiesIn: apin,
  })
  if err != nil {
    return nil, err
  }
  apout := new(dcom.ActivationProperties)
  if err = apout.Parse(cr.ActPropertiesOut); err != nil {
    return nil, err
  }
  if si := apout.SCMReplyInfoData(); si != nil {
    opts = append(opts, normalizeStringBindings(si.RemoteReply.OXIDBindings.GetStringBindings())...)
  } else {
    return nil, fmt.Errorf("remote create instance response: SCMReplyInfoData is nil")
  }
  if pi := apout.PropertiesOutInfo(); pi != nil && pi.InterfaceData != nil && len(pi.InterfaceData) > 0 {
    opts = append(opts, dcom.WithIPID(pi.InterfaceData[0].GetStandardObjectReference().Std.IPID))
  } else {
    return nil, fmt.Errorf("remote create instance response: PropertiesOutInfo is nil")
  }
  return opts, err
}

// remoteActivation activates a COM class on a remote machine using RemoteActivation (opnum 0).
func (m *Dcom) remoteActivation(ctx context.Context, conn dcerpc.Conn, cls *uuid.UUID, iid *dcom.IID) (opts []dcerpc.Option, err error) {
  if cls == nil {
    return nil, fmt.Errorf("class ID is nil")
  }
  ac, err := iactivation.NewActivationClient(ctx, conn)
  if err != nil {
    return nil, fmt.Errorf("init activation client: %w", err)
  }
  act, err := ac.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
    ORPCThis:                   &dcom.ORPCThis{Version: m.comVersion},
    ClassID:                    dtyp.GUIDFromUUID(cls),
    IIDs:                       []*dcom.IID{iid},
    RequestedProtocolSequences: []uint16{7, 15}, // ncacn_ip_tcp, ncacn_np
  })
  if err != nil {
    return nil, fmt.Errorf("remote activation: %w", err)
  }
  if act.HResult != 0 {
    return nil, hresult.FromCode(uint32(act.HResult))
  }
  return append(normalizeStringBindings(act.OXIDBindings.GetStringBindings()),
    dcom.WithIPID(act.InterfaceData[0].GetStandardObjectReference().Std.IPID)), nil
}
