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

// Package atexec implements remote command execution against a Windows host
// via the Task Scheduler service (TSCH) over the atsvc named pipe. It mirrors
// Impacket's atexec.py: register a one-shot scheduled task as LocalSystem,
// run it once, retrieve its captured output via SMB, then delete the task.
//
// The package is split from the cmd/atexec tool so it can be embedded in
// other Go projects without dragging the CLI flag and interactive shell logic.
//
// Typical usage from a third-party project:
//
//	pf, _ := smbClient.OpenPipe("atsvc")
//	rpc := dcerpc.NewClient(pf)
//	_ = rpc.BindAuth(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, creds)
//	ts := tsch.NewTaskScheduler(rpc)
//	res, err := atexec.Exec(ts, smbClient, "whoami /all", atexec.Options{})
package atexec

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/Mzack9999/goimpacket/pkg/dcerpc/tsch"
	"github.com/Mzack9999/goimpacket/pkg/smb"
)

// TaskXMLTemplate is the Impacket-compatible one-shot scheduled task XML.
// It is exposed so callers can drive RegisterTask directly when they need
// fully custom task definitions; Exec uses it under the hood.
const TaskXMLTemplate = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>`

// Options configures a single Exec invocation.
type Options struct {
	// Share is the writable share that holds the captured output file.
	// Defaults to "ADMIN$" - the output file lands in %windir%\Temp\<name>.
	Share string

	// Timeout caps how long Exec polls for output / task completion.
	// Defaults to 30s.
	Timeout time.Duration

	// NoOutput skips redirecting stdout/stderr and waits for task completion
	// instead of polling for an output file.
	NoOutput bool

	// Silent runs the command directly (split on the first space into
	// command + arguments) instead of wrapping it in cmd.exe /C ....
	Silent bool

	// SessionID, when >= 0, runs the task in the given Windows session via
	// SchRpcRun's lFlags + sessionId. Requires SYSTEM.
	SessionID int
}

// Result is the outcome of one Exec call.
type Result struct {
	// TaskName is the random task name registered under the root scheduler.
	TaskName string
	// OutputFile is the random temporary output file written under
	// %windir%\Temp on the chosen share. Empty when NoOutput is set.
	OutputFile string
	// Output is the captured stdout/stderr; empty when NoOutput is set or
	// the file never appeared within Timeout.
	Output string
}

// Exec registers a one-shot scheduled task that runs `command`, polls for
// its captured output via the supplied SMB client, and cleans the task up.
//
// ts must already be bound to the target's atsvc pipe (tsch UUID).
// smbClient must already be Connect()ed; Exec calls UseShare(opts.Share).
func Exec(ts *tsch.TaskScheduler, smbClient *smb.Client, command string, opts Options) (*Result, error) {
	if ts == nil {
		return nil, fmt.Errorf("atexec.Exec: TaskScheduler is required")
	}
	if smbClient == nil && !opts.NoOutput {
		return nil, fmt.Errorf("atexec.Exec: SMB client required to retrieve output (or set NoOutput)")
	}
	if command == "" {
		return nil, fmt.Errorf("atexec.Exec: command cannot be empty")
	}

	share := opts.Share
	if share == "" {
		share = "ADMIN$"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	taskName := generateRandomString(8)
	tmpFileName := generateRandomString(8) + ".tmp"

	cmd, args := buildCommandLine(command, tmpFileName, opts.Silent, opts.NoOutput)
	taskXML := fmt.Sprintf(TaskXMLTemplate, XMLEscape(cmd), XMLEscape(args))
	taskPath := "\\" + taskName

	if _, err := ts.RegisterTask(taskPath, taskXML, tsch.TASK_CREATE); err != nil {
		return nil, fmt.Errorf("register task: %w", err)
	}

	var runErr error
	if opts.SessionID >= 0 {
		runErr = ts.RunWithSessionId(taskPath, uint32(opts.SessionID))
	} else {
		runErr = ts.Run(taskPath)
	}
	if runErr != nil {
		_ = ts.Delete(taskPath)
		return nil, fmt.Errorf("run task: %w", runErr)
	}

	res := &Result{TaskName: taskName, OutputFile: tmpFileName}

	if opts.NoOutput {
		waitForTaskCompletion(ts, taskPath, timeout)
	} else {
		if err := smbClient.UseShare(share); err != nil {
			_ = ts.Delete(taskPath)
			return res, fmt.Errorf("use share %s: %w", share, err)
		}
		res.Output = pollOutput(smbClient, "Temp\\"+tmpFileName, timeout)
	}

	_ = ts.Delete(taskPath)
	return res, nil
}

// buildCommandLine constructs the (command, arguments) pair fed into the
// task XML, matching Impacket's behaviour:
//   - silent: split user input on first space; no shell wrapper, no output.
//   - default: wrap with cmd.exe /C and optionally redirect to %windir%\Temp.
func buildCommandLine(userCommand, tmpFileName string, silent, noOutput bool) (cmd, args string) {
	if silent {
		parts := strings.SplitN(userCommand, " ", 2)
		cmd = parts[0]
		if len(parts) > 1 {
			args = parts[1]
		}
		return cmd, args
	}
	cmd = "cmd.exe"
	if noOutput {
		args = fmt.Sprintf("/C %s", userCommand)
	} else {
		args = fmt.Sprintf("/C %s > %%windir%%\\Temp\\%s 2>&1", userCommand, tmpFileName)
	}
	return cmd, args
}

// waitForTaskCompletion polls SchRpcGetLastRunInfo until the task has run
// (or the timeout elapses). Used in NoOutput mode.
func waitForTaskCompletion(ts *tsch.TaskScheduler, taskPath string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		st, _, err := ts.GetLastRunInfo(taskPath)
		if err != nil {
			continue
		}
		if st.HasRun() {
			return
		}
	}
}

// pollOutput tails the captured output file via SMB. Empty string is returned
// if the file never materializes within timeout. The file is removed on success.
func pollOutput(smbClient *smb.Client, outputPath string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		content, err := smbClient.Cat(outputPath)
		if err == nil {
			_ = smbClient.Rm(outputPath)
			return content
		}
		// STATUS_SHARING_VIOLATION means the command is still writing.
		// STATUS_OBJECT_NAME_NOT_FOUND means the command hasn't started yet.
		// Anything else still falls through and we keep polling - the file
		// may take a moment to appear under load.
		_ = err
	}
	return ""
}

// XMLEscape mirrors Impacket's xml_escape helper. Exported so callers
// building their own task XML stay consistent with Impacket.
func XMLEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		`"`, "&quot;",
		"'", "&apos;",
		">", "&gt;",
		"<", "&lt;",
	)
	return r.Replace(s)
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
