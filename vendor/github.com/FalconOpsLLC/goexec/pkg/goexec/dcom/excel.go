package dcomexec

import (
  "context"
  "errors"
  "fmt"
  "strings"
  "syscall"

  "github.com/FalconOpsLLC/goexec/internal/util"
  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  "github.com/rs/zerolog"
)

const (
  MethodExcelMacro     = "Excel:ExecuteExcel4Macro"
  MethodExcelXLL       = "Excel:RegisterXLL"
  ExcelApplicationUuid = "00020812-0000-0000-C000-000000000046"
)

type DcomExcel struct {
  Dispatch
}

type DcomExcelMacro struct {
  DcomExcel
  Macros      []string
  MacroFile   string
  NoTerminate bool
}

type DcomExcelXll struct {
  DcomExcel
  XllLocation string
  NoTerminate bool
}

// Init will initialize the ShellBrowserWindow instance
func (m *DcomExcel) Init(ctx context.Context) (err error) {
  if err = m.Dcom.Init(ctx); err == nil {
    return m.getDispatch(ctx, uuid.MustParse(ExcelApplicationUuid))
  }
  return
}

// quit will terminate EXCEL.EXE via ExecuteExcel4Macro("QUIT()")
func (m *DcomExcel) quit(ctx context.Context) (err error) {
  log := zerolog.Ctx(ctx)
  quit := "QUIT()"
  log.Info().
    Str("call", "ExecuteExcel4Macro").
    Str("macro", quit).
    Msg("terminating Excel process")
  qr, err := m.callComMethod(ctx, nil, "ExecuteExcel4Macro", stringToVariant(quit))
  _ = qr
  if err != nil {
    if errors.Is(err, syscall.ECONNRESET) {
      log.Info().Msg("Excel process terminated")
      return nil
    }
    log.Warn().Err(err).Msgf(`Call ExecuteExcel4Macro("%s") failed`, quit)
  }
  if qr.Return != 0 {
    err = hresult.FromCode(uint32(qr.Return))
    log.Warn().Err(err).Msgf(`Call ExecuteExcel4Macro("%s"): %d`, quit, qr.Return)
  }

  return err
}

func (m *DcomExcelMacro) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {
  log := zerolog.Ctx(ctx)
  if len(m.Macros) == 0 {
    m.Macros = []string{fmt.Sprintf(`EXEC("%s")`, strings.ReplaceAll(execIO.String(), `"`, `""`))}
  }
  if !m.NoTerminate { // Terminate EXCEL.EXE via ExecuteExcel4Macro("QUIT()")
    defer func() {
      _ = m.quit(ctx)
    }()
  }
  for _, macro := range m.Macros {
    // Call ExecuteExcel4Macro to execute macro
    log.Info().
      Str("call", "ExecuteExcel4Macro").
      Str("macro", util.Truncate(macro, 100)).
      Msg("executing Excel macro")
    ir, err := m.callComMethod(ctx, nil, "ExecuteExcel4Macro", stringToVariant(macro))
    if err != nil {
      return err
    }
    if ir.Return != 0 {
      return hresult.FromCode(uint32(ir.Return))
    }
    log.Info().Msg("ExecuteExcel4Macro call successful")
  }

  return
}

func (m *DcomExcelXll) Call(ctx context.Context) (err error) {
  log := zerolog.Ctx(ctx)
  if !m.NoTerminate {
    defer func() {
      _ = m.quit(ctx)
    }()
  }
  qr, err := m.callComMethod(ctx, nil, "Application.RegisterXLL", stringToVariant(m.XllLocation))
  if err != nil {
    return fmt.Errorf("call RegisterXLL: %w", err)
  }
  log.Info().Msg("RegisterXLL call successful")
  if stat, ok := qr.VarResult.VarUnion.GetValue().(bool); ok && stat {
    log.Info().Bool("res", stat).Int32("return", qr.Return).Msg("XLL registered successfully")
  } else {
    log.Warn().Bool("res", stat).Int32("return", qr.Return).Msg("Execution may have failed")
  }
  return
}
