package scmrexec

import (
  "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
  "golang.org/x/text/encoding/unicode"
  "strings"
)

const (
  ErrorServiceRequestTimeout uint32 = 0x0000041d
  ErrorServiceNotActive      uint32 = 0x00000426

  ServiceDemandStart     uint32 = 0x00000003
  ServiceWin32OwnProcess uint32 = 0x00000010

  // https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights

  ServiceQueryConfig     uint32 = 0x00000001
  ServiceChangeConfig    uint32 = 0x00000002
  ServiceStart           uint32 = 0x00000010
  ServiceStop            uint32 = 0x00000020
  ServiceDelete          uint32 = 0x00010000 // special permission
  ServiceControlStop     uint32 = 0x00000001
  ScManagerCreateService uint32 = 0x00000002

  /*
        // Windows error codes
        ERROR_FILE_NOT_FOUND          uint32 = 0x00000002
        ERROR_SERVICE_DOES_NOT_EXIST  uint32 = 0x00000424

     // Windows service/scm constants
     SERVICE_BOOT_START   uint32 = 0x00000000
     SERVICE_SYSTEM_START uint32 = 0x00000001
     SERVICE_AUTO_START   uint32 = 0x00000002
     SERVICE_DISABLED     uint32 = 0x00000004

     // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/4e91ff36-ab5f-49ed-a43d-a308e72b0b3c
     SERVICE_CONTINUE_PENDING uint32 = 0x00000005
     SERVICE_PAUSE_PENDING    uint32 = 0x00000006
     SERVICE_PAUSED           uint32 = 0x00000007
     SERVICE_RUNNING          uint32 = 0x00000004
     SERVICE_START_PENDING    uint32 = 0x00000002
     SERVICE_STOP_PENDING     uint32 = 0x00000003
     SERVICE_STOPPED          uint32 = 0x00000001
  */

  ServiceDeleteAccess = ServiceDelete
  ServiceModifyAccess = ServiceQueryConfig | ServiceChangeConfig | ServiceStop | ServiceStart | ServiceDelete
  ServiceCreateAccess = ScManagerCreateService | ServiceStart | ServiceStop | ServiceDelete
  ServiceAllAccess    = ServiceCreateAccess | ServiceModifyAccess
)

type service struct {
  name           string
  handle         *svcctl.Handle
  originalConfig *svcctl.QueryServiceConfigW
}

// parseDependencies will parse the dependencies returned from a RQueryServiceConfigW
// response (svcctl.QueryServiceConfigWResponse) into a raw byte array compatible with
// the lpDependencies field as defined in the microsoft docs.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/3ab258d6-87b0-459e-8d83-a2cdd8038b78
func parseDependencies(deps string) (out []byte) {
  if deps != "" && deps != "/" {

    if out, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes(
      []byte(strings.ReplaceAll(deps, "/", "\x00") + "\x00"),
    ); err == nil {
      return out
    }
  }
  return nil
}
