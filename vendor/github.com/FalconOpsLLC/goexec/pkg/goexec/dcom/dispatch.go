package dcomexec

import (
  "context"
  "fmt"
  "strings"

  "github.com/oiweiwei/go-msrpc/dcerpc"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut/idispatch/v0"

  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

const (
  LcEnglishUs uint32 = 0x409
)

// Dispatch represents a DCOM IDispatch client
type Dispatch struct {
  Dcom
  dispatch idispatch.DispatchClient
}

// getDispatch will create an IDispatch instance of the provided class
func (m *Dispatch) getDispatch(ctx context.Context, cls *uuid.UUID) error {
  opts, err := m.bindInstance(ctx, cls, idispatch.DispatchIID)
  if err != nil {
    return err
  }
  m.dispatch, err = idispatch.NewDispatchClient(ctx, m.Client.Dce(), opts...) // Might need those dcerpc.Options?
  if err != nil {
    return fmt.Errorf("init IDispatch client: %w", err)
  }
  return nil
}

// callComMethod calls a COM method on a remote object using the IDispatch interface.
//
// The method is specified as a dot-separated string, e.g. "ShellWindows.Item" to call the Item method on the ShellWindows object.
//
// The method arguments are passed as *oaut.Variant.
//
// The method returns an *idispatch.InvokeResponse, which contains the result of the method call.
//
// The method will automatically follow the IDispatch interface to get the object specified in the method name, e.g. "ShellWindows.Item" will
// automatically call "ShellWindows.Item.QueryInterface" to get the IDispatch interface of the object, then call "Item.Invoke" to call the method.
func (m *Dispatch) callComMethod(ctx context.Context, id *dcom.IPID, method string, args ...*oaut.Variant) (ir *idispatch.InvokeResponse, err error) {
  parts := strings.Split(method, ".")

  for i, obj := range parts {
    var opts []dcerpc.CallOption
    if id != nil {
      opts = append(opts, dcom.WithIPID(id))
    }
    gr, err := m.dispatch.GetIDsOfNames(ctx, &idispatch.GetIDsOfNamesRequest{
      This:     &dcom.ORPCThis{Version: m.comVersion},
      IID:      &dcom.IID{},
      LocaleID: LcEnglishUs,
      Names:    []string{obj},
    }, opts...)
    if err != nil {
      return nil, fmt.Errorf("call %q: get dispatch ID of name %q: %w", method, obj, err)
    }
    if len(gr.DispatchID) < 1 {
      return nil, fmt.Errorf("call %q: dispatch ID of name %q not found", method, obj)
    }
    irq := &idispatch.InvokeRequest{
      This:             &dcom.ORPCThis{Version: m.comVersion},
      IID:              &dcom.IID{},
      LocaleID:         LcEnglishUs,
      DispatchIDMember: gr.DispatchID[0],
    }
    if i >= len(parts)-1 {
      irq.Flags = 1
      irq.DispatchParams = &oaut.DispatchParams{Args: args}
      return m.dispatch.Invoke(ctx, irq, opts...)
    }
    irq.Flags = 2
    ir, err = m.dispatch.Invoke(ctx, irq, opts...)
    if err != nil {
      return nil, fmt.Errorf("call %q: get properties of object %q: %w", method, obj, err)
    }
    di, ok := ir.VarResult.VarUnion.GetValue().(*oaut.Dispatch)
    if !ok {
      return nil, fmt.Errorf("call %q: invalid dispatch object for %q", method, obj)
    }
    id = di.InterfacePointer().GetStandardObjectReference().Std.IPID
  }
  return
}
