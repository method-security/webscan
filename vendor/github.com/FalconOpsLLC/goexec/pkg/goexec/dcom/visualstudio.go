package dcomexec

import "github.com/rs/zerolog"

/*
See https://learn.microsoft.com/en-us/dotnet/api/envdte._dte.executecommand
*/

import (
  "context"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/midl/uuid"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  MethodVisualStudioDTE   = "VisualStudio.DTE:ExecuteCommand"
  VisualStudioDteUuid     = "33ABD590-0400-4FEF-AF98-5F5A8A99CFC3"
  VisualStudioDte2019Uuid = "2E1517DA-87BF-4443-984A-D2BF18F5A908"
)

type DcomVisualStudioDte struct {
  Dispatch
  // Is2019 indicates that the installation is Visual Studio 2019
  Is2019 bool
  // CommandName is the name of the DTE command to invoke
  CommandName string
  // CommandArgs are the arguments to pass to the command
  CommandArgs string
}

func (m *DcomVisualStudioDte) Init(ctx context.Context) (err error) {
  if err = m.Dcom.Init(ctx); err == nil {
    if m.Is2019 {
      return m.getDispatch(ctx, uuid.MustParse(VisualStudioDte2019Uuid))
    }
    return m.getDispatch(ctx, uuid.MustParse(VisualStudioDteUuid))
  }
  return
}

func (m *DcomVisualStudioDte) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {
  log := zerolog.Ctx(ctx)
  dteCmd := m.CommandName
  dteArgs := m.CommandArgs
  if dteCmd == "" {
    dteCmd = "tools.shell"
    dteArgs = execIO.String()
  }
  defer func() {
    // Terminate devenv.exe
    q, err := m.callComMethod(ctx, nil, "Quit")
    if err != nil {
      log.Warn().Err(err).Msg("Call to Quit() failed")
      return
    }
    zerolog.Ctx(ctx).Info().Int32("return", q.Return).Msg("Quit called")
  }()
  log.Info().Str("command", dteCmd).Str("args", dteArgs).Msg("Executing DTE command")
  ir, err := m.callComMethod(ctx, nil, "ExecuteCommand", stringToVariant(dteArgs), stringToVariant(dteCmd))
  if err == nil {
    log.Info().Int32("return", ir.Return).Msg("ExecuteCommand called")
  }
  return
}
