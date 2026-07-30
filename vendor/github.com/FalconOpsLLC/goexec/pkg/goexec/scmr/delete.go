package scmrexec

import (
  "context"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
)

const (
  MethodDelete = "Delete"
)

type ScmrDelete struct {
  Scmr
  goexec.Cleaner

  IO goexec.ExecutionIO

  ServiceName string
}

func (m *ScmrDelete) Call(ctx context.Context) (err error) {

  svc, err := m.openService(ctx, m.ServiceName)
  if err != nil {
    return err
  }
  defer m.AddCleaners(func(ctxInner context.Context) error { return m.closeService(ctx, svc) })

  return m.deleteService(ctx, svc)
}
