package dcomexec

import (
  "context"

  "github.com/oiweiwei/go-msrpc/msrpc/dcom"
)

type contextKey string

const (
  // contextKeyComVersion (dcom.COMVersion) carries the effective COM version
  contextKeyComVersion          contextKey = "ComVersion"
  contextDefaultComVersionMajor uint16     = 5
  contextDefaultComVersionMinor uint16     = 7

  // contextKeyGetComVersion (bool) determines whether to call getComVersion (ServerAlive2) to determine the COM version.
  // If this is false, defaultComVersionMajor, contextDefaultComVersionMinor will be used.
  contextKeyGetComVersion     contextKey = "GetComVersion"
  contextDefaultGetComVersion            = true

  contextKeyCreateInstanceMethod     contextKey = "CreateInstanceMethod"
  contextDefaultCreateInstanceMethod            = OptRemoteCreateInstance
)

func contextGetComVersion(ctx context.Context) bool {
  if v := ctx.Value(contextKeyGetComVersion); v != nil {
    if g, ok := v.(bool); ok {
      return g
    }
  }
  return contextDefaultGetComVersion
}

// contextComVersion will return the effective COM version (*dcom.COMVersion) from a context.
// If no COM Version is set and GetComVersion is true, nil is returned
func contextComVersion(ctx context.Context) *dcom.COMVersion {
  if v := ctx.Value(contextKeyComVersion); v != nil {
    if g, ok := v.(dcom.COMVersion); ok {
      return &g
    }
  }
  if !contextGetComVersion(ctx) {
    return &dcom.COMVersion{
      MajorVersion: contextDefaultComVersionMajor,
      MinorVersion: contextDefaultComVersionMinor,
    }
  }
  return nil
}

func contextCreateInstanceMethod(ctx context.Context) string {
  if v := ctx.Value(contextKeyCreateInstanceMethod); v != nil {
    if g, ok := v.(string); ok {
      return g
    }
  }
  return contextDefaultCreateInstanceMethod
}
