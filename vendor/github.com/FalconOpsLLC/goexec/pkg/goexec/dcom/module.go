package dcomexec

import (
  "context"
  "fmt"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/FalconOpsLLC/goexec/pkg/goexec/dce"
  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  ModuleName = "DCOM"
)

type Dcom struct {
  goexec.Cleaner
  goexec.Executor

  Client     *dce.Client
  comVersion *dcom.COMVersion
}

func (m *Dcom) Connect(ctx context.Context) (err error) {
  if err = m.Client.Connect(ctx); err == nil {
    m.AddCleaners(m.Client.Close)
  }
  return
}

func (m *Dcom) Init(ctx context.Context) (err error) {
  if m.comVersion = contextComVersion(ctx); m.comVersion == nil {
    m.comVersion, err = getComVersion(ctx, m.Client.Dce())
    if err != nil {
      return fmt.Errorf("get COM version: %w", err)
    }
  }
  return
}

func (m *Dcom) bindInstance(ctx context.Context, cls *uuid.UUID, iid *dcom.IID) (opts []dcerpc.Option, err error) {
  if mt := contextCreateInstanceMethod(ctx); mt == OptRemoteCreateInstance {
    opts, err = m.remoteCreateInstance(ctx, m.Client.Dce(), cls, iid)
  } else if mt == OptRemoteActivation {
    opts, err = m.remoteActivation(ctx, m.Client.Dce(), cls, iid)
  } else {
    return nil, fmt.Errorf("invalid create instance method: %s", mt)
  }
  if err != nil {
    return nil, fmt.Errorf("create instance: %w", err)
  }
  return opts, m.Client.Reconnect(ctx, opts...)
}
