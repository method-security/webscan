// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package wmiexec implements remote command execution against a Windows host
// over DCOM Win32_Process.Create (Impacket's wmiexec.py) on top of the
// oiweiwei/go-msrpc DCOM stack. It is a library so other Go projects can issue
// WMI exec commands without forking the wmiexec CLI.
//
// The package separates concerns:
//
//   - Session encapsulates an authenticated WMI session ready to issue many
//     Win32_Process.Create calls. Build it with Dial.
//   - Exec is the one-shot helper that opens a Session, runs a single command,
//     retrieves the output via SMB, then tears the session down.
//   - NewNTLMContext / NewKerberosContext return a per-call gssapi context so
//     the package never touches process-global gssapi state. This makes it
//     safe to use from concurrent callers.
//
// The package supports NTLM password, pass-the-hash, and Kerberos (via
// ccache) authentication. Output retrieval requires an SMB client; one will
// be opened automatically against ADMIN$ if the caller does not provide one.
package wmiexec

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	iactivation "github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	iobjectexporter "github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	iwbemlevel1login "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	iwbemservices "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio/query"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	gokrb5config "github.com/oiweiwei/gokrb5.fork/v9/config"
	gokrb5credentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/Mzack9999/goimpacket/pkg/session"
	"github.com/Mzack9999/goimpacket/pkg/smb"
)

// DefaultShell mirrors Impacket wmiexec.py's default cmd.exe wrapper.
const DefaultShell = "cmd.exe /Q /c "

// DialOptions configure how a WMI session is established.
type DialOptions struct {
	// Dialer optionally routes go-msrpc's TCP dials. If nil, go-msrpc's
	// default dialer is used. Set this to plug into a custom dialer so all
	// DCOM traffic honors the caller's network policy.
	Dialer dcerpc.Dialer

	// SMB is an already-Connected SMB client used for output retrieval.
	// If nil, Exec / Session.Exec will open a fresh SMB session against
	// the target (NTLM password / hash credentials only).
	SMB *smb.Client

	// KerberosCCache, if non-empty, switches authentication to Kerberos
	// using this credential cache. Required only when creds.UseKerberos is
	// true; the env KRB5CCNAME is used as a fallback.
	KerberosCCache string

	// SecurityOpts allow callers to inject extra dcerpc security options
	// (e.g. dcerpc.WithSeal). dcerpc.WithSign is always added.
	SecurityOpts []dcerpc.Option
}

// Options configure a single Exec / Session.Exec call.
type Options struct {
	// Share is the writable share that will hold the captured output file.
	// Defaults to "ADMIN$".
	Share string

	// Shell is the cmd-style shell prefix; defaults to "cmd.exe /Q /c ".
	Shell string

	// ShellType selects the wrapper. "cmd" (default) or "powershell".
	ShellType string

	// PWD overrides the working directory that the wrapped shell cd's to
	// before running the command. Defaults to "C:\\".
	PWD string

	// NoOutput skips capturing stdout/stderr.
	NoOutput bool

	// Stealth runs the command directly through Win32_Process.Create with
	// no cmd.exe wrapper. Implies NoOutput in practice.
	Stealth bool

	// Timeout caps how long Exec polls for the output file. Default 30s.
	Timeout time.Duration
}

// Result is the outcome of one Exec / Session.Exec call.
type Result struct {
	// ReturnValue is the Win32_Process.Create ReturnValue (0 on success).
	ReturnValue uint32
	// OutputFile is the random output file name written under the share.
	// Empty when NoOutput / Stealth.
	OutputFile string
	// Output is the captured stdout/stderr; empty when NoOutput / Stealth
	// or when the file never appeared within Timeout.
	Output string
}

// Session is an authenticated WMI session that can run multiple commands.
type Session struct {
	target session.Target
	creds  *session.Credentials

	ctx     context.Context
	wmiCtx  context.Context
	srv     *iobjectexporter.ServerAlive2Response
	svcs    iwbemservices.ServicesClient
	conn    dcerpc.Conn // OXID connection
	cc      dcerpc.Conn // EPM connection
	smb     *smb.Client // for output retrieval
	ownsSMB bool
}

// Dial authenticates against the target's WMI service and returns a Session
// ready to run Win32_Process.Create commands.
func Dial(ctx context.Context, target session.Target, creds *session.Credentials, dopts DialOptions) (*Session, error) {
	if creds == nil {
		return nil, fmt.Errorf("wmiexec.Dial: credentials are required")
	}

	gssCtx, err := newSecurityContext(ctx, target, creds, dopts.KerberosCCache)
	if err != nil {
		return nil, err
	}

	securityOpts := append([]dcerpc.Option{dcerpc.WithSign()}, dopts.SecurityOpts...)
	if creds.UseKerberos {
		securityOpts = append(securityOpts, dcerpc.WithTargetName("host/"+target.Host))
	}

	transportOpts := []dcerpc.Option{}
	if dopts.Dialer != nil {
		transportOpts = append(transportOpts, dcerpc.WithDialer(dopts.Dialer))
	}

	dialOpts := append(append([]dcerpc.Option{}, transportOpts...), securityOpts...)

	cc, err := dcerpc.Dial(gssCtx, net.JoinHostPort(target.Host, "135"), dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial 135: %w", err)
	}
	closeOnError := func() { _ = cc.Close(gssCtx) }

	oxp, err := iobjectexporter.NewObjectExporterClient(gssCtx, cc, securityOpts...)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("ObjectExporterClient: %w", err)
	}
	srv, err := oxp.ServerAlive2(gssCtx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("ServerAlive2: %w", err)
	}

	actClient, err := iactivation.NewActivationClient(gssCtx, cc, securityOpts...)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("ActivationClient: %w", err)
	}
	act, err := actClient.RemoteActivation(gssCtx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{7},
	})
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("RemoteActivation: %w", err)
	}
	if act.HResult != 0 {
		closeOnError()
		return nil, fmt.Errorf("RemoteActivation hresult: %s", hresult.FromCode(uint32(act.HResult)))
	}

	std := act.InterfaceData[0].GetStandardObjectReference().Std
	endpoints := act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")
	if len(endpoints) == 0 {
		closeOnError()
		return nil, fmt.Errorf("no ncacn_ip_tcp endpoints returned by activator")
	}

	wcc, err := dcerpc.Dial(gssCtx, target.Host, append(dialOpts, transportOpts...)...)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("dial WMI: %w", err)
	}

	wmiCtx := gssapi.NewSecurityContext(gssCtx)
	wmiOpts := append([]dcerpc.Option{dcom.WithIPID(std.IPID)}, securityOpts...)
	l1login, err := iwbemlevel1login.NewLevel1LoginClient(wmiCtx, wcc, wmiOpts...)
	if err != nil {
		_ = wcc.Close(gssCtx)
		closeOnError()
		return nil, fmt.Errorf("Level1LoginClient: %w", err)
	}
	login, err := l1login.NTLMLogin(wmiCtx, &iwbemlevel1login.NTLMLoginRequest{
		This:            &dcom.ORPCThis{Version: srv.COMVersion},
		NetworkResource: "//./root/cimv2",
	})
	if err != nil {
		_ = wcc.Close(gssCtx)
		closeOnError()
		return nil, fmt.Errorf("NTLMLogin: %w", err)
	}

	ns := login.Namespace
	svcsOpts := append([]dcerpc.Option{dcom.WithIPID(ns.InterfacePointer().IPID())}, securityOpts...)
	svcs, err := iwbemservices.NewServicesClient(wmiCtx, wcc, svcsOpts...)
	if err != nil {
		_ = wcc.Close(gssCtx)
		closeOnError()
		return nil, fmt.Errorf("ServicesClient: %w", err)
	}

	s := &Session{
		target: target, creds: creds,
		ctx: gssCtx, wmiCtx: wmiCtx, srv: srv, svcs: svcs,
		conn: wcc, cc: cc, smb: dopts.SMB,
	}
	if dopts.SMB == nil {
		// We open the SMB session lazily on first Exec that needs output
		// so callers using NoOutput / Stealth don't pay the cost.
		s.ownsSMB = true
	}
	return s, nil
}

// Close releases the WMI session's underlying RPC connections (and the
// auto-opened SMB session when applicable).
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.ownsSMB && s.smb != nil {
		s.smb.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close(s.ctx)
	}
	if s.cc != nil {
		_ = s.cc.Close(s.ctx)
	}
	return nil
}

// Exec runs a single command on the session's target.
func (s *Session) Exec(command string, opts Options) (*Result, error) {
	if command == "" {
		return nil, fmt.Errorf("wmiexec: command cannot be empty")
	}
	share := opts.Share
	if share == "" {
		share = "ADMIN$"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	shell := opts.Shell
	if shell == "" {
		shell = DefaultShell
	}
	pwd := opts.PWD
	if pwd == "" {
		pwd = "C:\\"
	}

	final, outputFile := buildCommandLine(command, shell, opts.ShellType, share, pwd, opts.NoOutput, opts.Stealth)

	args := wmio.Values{
		"CommandLine":      final,
		"CurrentDirectory": nil,
	}
	out, err := query.NewBuilder(s.wmiCtx, s.svcs, s.srv.COMVersion).
		Spawn("Win32_Process").
		Method("Create").
		Values(args, wmio.JSONValueToType).
		Exec().
		Object()
	if err != nil {
		return nil, fmt.Errorf("Win32_Process.Create: %w", err)
	}

	res := &Result{OutputFile: outputFile}
	if vals := out.Values(); vals != nil {
		if v, ok := vals["ReturnValue"]; ok {
			res.ReturnValue = toUint32(v)
		}
	}

	if outputFile == "" {
		return res, nil
	}

	if err := s.ensureSMB(share); err != nil {
		return res, err
	}
	res.Output = pollOutput(s.smb, outputFile, timeout)
	return res, nil
}

// ensureSMB opens (or reuses) the output-retrieval SMB session and binds
// the requested share.
func (s *Session) ensureSMB(share string) error {
	if s.smb == nil {
		c := smb.NewClient(s.target, s.creds)
		if err := c.Connect(); err != nil {
			return fmt.Errorf("smb connect: %w", err)
		}
		s.smb = c
		s.ownsSMB = true
	}
	if err := s.smb.UseShare(share); err != nil {
		return fmt.Errorf("use share %s: %w", share, err)
	}
	return nil
}

// Exec is a convenience wrapper that opens a Session, runs one command,
// then closes the session. For repeated commands against the same target
// callers should keep a Session open.
func Exec(ctx context.Context, target session.Target, creds *session.Credentials, command string, opts Options, dopts DialOptions) (*Result, error) {
	s, err := Dial(ctx, target, creds, dopts)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Exec(command, opts)
}

// buildCommandLine reproduces wmiexec.py's command wrapping logic.
// Returns (finalCommand, outputFileName). outputFileName is empty when
// NoOutput / Stealth.
func buildCommandLine(command, shell, shellType, share, pwd string, noOutput, stealth bool) (string, string) {
	var outputFile string

	if shellType == "powershell" && !stealth {
		psCommand := "$ProgressPreference='SilentlyContinue';" + command
		encoded := encodeUTF16LEBase64(psCommand)
		psPrefix := "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "
		if !noOutput {
			outputFile = generateRandomFilename()
			return fmt.Sprintf("cmd.exe /Q /c (cd /d %s && %s%s) 1> \\\\127.0.0.1\\%s\\%s 2>&1",
				pwd, psPrefix, encoded, share, outputFile), outputFile
		}
		return fmt.Sprintf("cmd.exe /Q /c cd /d %s && %s%s", pwd, psPrefix, encoded), ""
	}

	cmdWithDir := command
	if !stealth {
		cmdWithDir = fmt.Sprintf("cd /d %s && %s", pwd, command)
	}
	if !noOutput && !stealth {
		outputFile = generateRandomFilename()
		return fmt.Sprintf("%s(%s) 1> \\\\127.0.0.1\\%s\\%s 2>&1", shell, cmdWithDir, share, outputFile), outputFile
	}
	if stealth {
		return command, ""
	}
	return shell + cmdWithDir, ""
}

// pollOutput tails the captured output file via SMB until it appears
// or timeout expires. The file is removed on success.
func pollOutput(c *smb.Client, filename string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		content, err := c.Cat(filename)
		if err == nil && content != "" {
			_ = c.Rm(filename)
			return content
		}
		if err != nil &&
			!strings.Contains(err.Error(), "STATUS_SHARING_VIOLATION") &&
			!strings.Contains(err.Error(), "STATUS_OBJECT_NAME_NOT_FOUND") &&
			content == "" {
			// Unknown errors fall through; we keep polling because some
			// SMB servers emit transient faults right after task launch.
			_ = err
		}
	}
	return ""
}

// newSecurityContext builds a per-call gssapi context primed with the
// requested credentials and mechanisms. Process-global gssapi state is
// not touched. Returns ErrNoCredentials when no usable secret is provided.
func newSecurityContext(parent context.Context, target session.Target, creds *session.Credentials, ccachePath string) (context.Context, error) {
	fullUser := creds.Username
	if creds.Domain != "" {
		fullUser = creds.Domain + "\\" + creds.Username
	}

	switch {
	case creds.UseKerberos:
		path := ccachePath
		if path == "" {
			path = os.Getenv("KRB5CCNAME")
		}
		if path == "" {
			local := creds.Username + ".ccache"
			if _, err := os.Stat(local); err == nil {
				path = local
			}
		}
		if path == "" {
			return nil, fmt.Errorf("wmiexec: kerberos requires a ccache path or KRB5CCNAME")
		}
		ccache, err := gokrb5credentials.LoadCCache(path)
		if err != nil {
			return nil, fmt.Errorf("load ccache %s: %w", path, err)
		}
		realm := strings.ToUpper(creds.Domain)
		kdc := target.Host
		if creds.DCIP != "" {
			kdc = creds.DCIP
		}
		conf := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = %s
    }
`, realm, realm, kdc)
		krb5Conf, err := gokrb5config.NewFromString(conf)
		if err != nil {
			return nil, fmt.Errorf("krb5 config: %w", err)
		}
		krbConfig := krb5.NewConfig()
		krbConfig.KRB5Config = krb5.ParsedLibDefaults(krb5Conf)
		krbConfig.DCEStyle = true

		return gssapi.NewSecurityContext(parent,
			gssapi.WithCredential(credential.NewFromCCache(fullUser, ccache)),
			gssapi.WithMechanismFactory(ssp.SPNEGO),
			gssapi.WithMechanismFactory(ssp.KRB5, krbConfig),
		), nil

	case creds.Hash != "":
		nt := creds.Hash
		if i := strings.IndexByte(nt, ':'); i >= 0 {
			nt = nt[i+1:]
		}
		return gssapi.NewSecurityContext(parent,
			gssapi.WithCredential(credential.NewFromNTHash(fullUser, nt)),
			gssapi.WithMechanismFactory(ssp.NTLM),
			gssapi.WithMechanismFactory(ssp.SPNEGO),
		), nil

	case creds.Password != "":
		return gssapi.NewSecurityContext(parent,
			gssapi.WithCredential(credential.NewFromPassword(fullUser, creds.Password)),
			gssapi.WithMechanismFactory(ssp.NTLM),
			gssapi.WithMechanismFactory(ssp.SPNEGO),
		), nil

	default:
		return nil, fmt.Errorf("wmiexec: no password / hash / kerberos cred provided")
	}
}

func toUint32(v any) uint32 {
	switch x := v.(type) {
	case uint32:
		return x
	case int32:
		return uint32(x)
	case uint64:
		return uint32(x)
	case int64:
		return uint32(x)
	case int:
		return uint32(x)
	case float64:
		return uint32(x)
	default:
		var u uint32
		_, _ = fmt.Sscan(fmt.Sprint(v), &u)
		return u
	}
}

// encodeUTF16LEBase64 encodes a string to UTF-16LE Base64 (PowerShell -Enc).
func encodeUTF16LEBase64(s string) string {
	utf16Chars := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func generateRandomFilename() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x.txt", b)
}
