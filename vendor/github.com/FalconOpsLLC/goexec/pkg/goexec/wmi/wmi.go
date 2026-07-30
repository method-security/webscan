package wmiexec

import "github.com/oiweiwei/go-msrpc/msrpc/dcom"

const (
  ProtocolSequenceRPC uint16 = 7
  ProtocolSequenceNP  uint16 = 15
)

var (
  ComVersion = &dcom.COMVersion{
    MajorVersion: 5,
    MinorVersion: 7,
  }
  ORPCThis = &dcom.ORPCThis{Version: ComVersion}
)
