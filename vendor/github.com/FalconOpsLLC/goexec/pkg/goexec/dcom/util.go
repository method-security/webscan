package dcomexec

import (
  "context"

  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// getComVersion uses IObjectExporter.ServerAlive2() to determine the COM version of the server.
// If a COM version can be determined from the context, then IObjectExporter.ServerAlive2 will not be called
func getComVersion(ctx context.Context, cc dcerpc.Conn) (ver *dcom.COMVersion, err error) {
  cv := contextComVersion(ctx)
  if cv == nil {
    oe, err := iobjectexporter.NewObjectExporterClient(ctx, cc)
    if err != nil {
      return nil, err
    }
    srv, err := oe.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
    if err != nil {
      return nil, err
    }
    return srv.COMVersion, nil
  }
  return cv, nil
}

// normalizeStringBindings removes the address/hostname from string bindings to prevent name resolution issues.
func normalizeStringBindings(bindings []*dcom.StringBinding) (opts []dcerpc.Option) {
  for _, b := range bindings {
    if s, err := dcerpc.ParseStringBinding(b.String()); err == nil {
      s.NetworkAddress = ""
      opts = append(opts, dcerpc.WithEndpoint(s.String()))
    }
  }
  return
}

// stringToVariant converts a string to a *oaut.Variant.
func stringToVariant(s string) *oaut.Variant {
  return &oaut.Variant{
    Size: 5,
    VT:   8,
    VarUnion: &oaut.Variant_VarUnion{
      Value: &oaut.Variant_VarUnion_BSTR{
        BSTR: &oaut.String{
          Data: s,
        },
      },
    },
  }
}
