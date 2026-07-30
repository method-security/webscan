package dcomexec

import (
  "context"
  "errors"
  "fmt"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
  "github.com/rs/zerolog/log"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  MethodShellWindows = "ShellWindows" // ShellWindows::Item().Document.Application.ShellExecute
  ShellWindowsUuid   = "9BA05972-F6A8-11CF-A442-00A0C90A8F39"
)

type DcomShellWindows struct {
  Dispatch

  WorkingDirectory string
  WindowState      string
}

// Init will initialize the ShellWindows instance
func (m *DcomShellWindows) Init(ctx context.Context) (err error) {
  if err = m.Dcom.Init(ctx); err == nil {
    return m.getDispatch(ctx, uuid.MustParse(ShellWindowsUuid))
  }
  return
}

// Execute will perform command execution via the ShellWindows object. See https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
func (m *DcomShellWindows) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {
  method := "Item"

  iv, err := m.callComMethod(ctx, nil, "Item")
  if err != nil {
    log.Error().Err(err).Msg("Failed to call method")
    return fmt.Errorf("call method %q: %w", method, err)
  }
  item, ok := iv.VarResult.VarUnion.GetValue().(*oaut.Dispatch)
  if !ok {
    return errors.New("failed to get dispatch from ShellWindows::Item()")
  }
  method = "Document.Application.ShellExecute"
  cmdline := execIO.CommandLine()

  // Arguments must be passed in reverse order
  if _, err := m.callComMethod(ctx, item.InterfacePointer().GetStandardObjectReference().Std.IPID, method,
    stringToVariant(m.WindowState),
    stringToVariant(""), // FUTURE?
    stringToVariant(m.WorkingDirectory),
    stringToVariant(cmdline[1]),
    stringToVariant(cmdline[0])); err != nil {
    return fmt.Errorf("call %q: %w", method, err)
  }
  log.Info().Msg("Method call successful")
  return
}
