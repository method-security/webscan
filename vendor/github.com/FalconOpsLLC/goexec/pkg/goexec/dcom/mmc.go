package dcomexec

import (
  "context"
  "fmt"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/rs/zerolog"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  MethodMmc = "MMC20.Application" // MMC20.Application::Document.ActiveView.ExecuteShellCommand
  MmcUuid   = "49B2791A-B1AE-4C90-9B8E-E860BA07F889"
)

type DcomMmc struct {
  Dispatch
  WorkingDirectory string
  WindowState      string
}

// Init will initialize the ShellBrowserWindow instance
func (m *DcomMmc) Init(ctx context.Context) (err error) {
  if err = m.Dcom.Init(ctx); err == nil {
    return m.getDispatch(ctx, uuid.MustParse(MmcUuid))
  }
  return
}

// Execute will perform command execution via the MMC20.Application DCOM object.
func (m *DcomMmc) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {
  method := "Document.ActiveView.ExecuteShellCommand"
  log := zerolog.Ctx(ctx).With().Str("method", method).Logger()
  cmdline := execIO.CommandLine()

  // Arguments must be passed in reverse order
  if _, err := m.callComMethod(ctx, nil, method,
    stringToVariant(m.WindowState),
    stringToVariant(cmdline[1]),
    stringToVariant(m.WorkingDirectory),
    stringToVariant(cmdline[0])); err != nil {

    return fmt.Errorf("call %q: %w", method, err)
  }
  log.Info().Msg("Method call successful")
  return
}
