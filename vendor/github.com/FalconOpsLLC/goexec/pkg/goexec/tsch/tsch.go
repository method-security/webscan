package tschexec

import (
  "encoding/xml"
  "fmt"
  "regexp"
  "time"
)

const (
  TaskXmlHeader         = `<?xml version="1.0" encoding="UTF-16"?>`
  TaskXmlNamespace      = "http://schemas.microsoft.com/windows/2004/02/mit/task"
  TaskXmlVersion        = "1.2"
  TaskXmlDurationFormat = "2006-01-02T15:04:05.9999999Z"
)

var (
  TaskPathRegex = regexp.MustCompile(`^\\[^ :/\\][^:/]*$`)
  TaskNameRegex = regexp.MustCompile(`^[^ :/\\][^:/\\]*$`)
)

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/0d6383e4-de92-43e7-b0bb-a60cfa36379f

type taskTriggers struct {
  XMLName      xml.Name          `xml:"Triggers"`
  TimeTriggers []taskTimeTrigger `xml:"TimeTrigger,omitempty"`
}

type taskTimeTrigger struct {
  XMLName       xml.Name `xml:"TimeTrigger"`
  StartBoundary string   `xml:"StartBoundary,omitempty"` // Derived from time.Time
  EndBoundary   string   `xml:"EndBoundary,omitempty"`   // Derived from time.Time; must be > StartBoundary
  Enabled       bool     `xml:"Enabled"`
}

type taskIdleSettings struct {
  XMLName       xml.Name `xml:"IdleSettings"`
  StopOnIdleEnd bool     `xml:"StopOnIdleEnd"`
  RestartOnIdle bool     `xml:"RestartOnIdle"`
}

type taskSettings struct {
  XMLName                    xml.Name         `xml:"Settings"`
  Enabled                    bool             `xml:"Enabled"`
  Hidden                     bool             `xml:"Hidden"`
  DisallowStartIfOnBatteries bool             `xml:"DisallowStartIfOnBatteries"`
  StopIfGoingOnBatteries     bool             `xml:"StopIfGoingOnBatteries"`
  AllowHardTerminate         bool             `xml:"AllowHardTerminate"`
  RunOnlyIfNetworkAvailable  bool             `xml:"RunOnlyIfNetworkAvailable"`
  AllowStartOnDemand         bool             `xml:"AllowStartOnDemand"`
  WakeToRun                  bool             `xml:"WakeToRun"`
  RunOnlyIfIdle              bool             `xml:"RunOnlyIfIdle"`
  StartWhenAvailable         bool             `xml:"StartWhenAvailable"`
  Priority                   int              `xml:"Priority,omitempty"` // 1 to 10 inclusive
  MultipleInstancesPolicy    string           `xml:"MultipleInstancesPolicy,omitempty"`
  ExecutionTimeLimit         string           `xml:"ExecutionTimeLimit,omitempty"`
  DeleteExpiredTaskAfter     string           `xml:"DeleteExpiredTaskAfter,omitempty"` // Derived from time.Duration
  IdleSettings               taskIdleSettings `xml:"IdleSettings,omitempty"`
}

type taskActionExec struct {
  XMLName   xml.Name `xml:"Exec"`
  Command   string   `xml:"Command"`
  Arguments string   `xml:"Arguments,omitempty"`
}

type taskActions struct {
  XMLName xml.Name         `xml:"Actions"`
  Context string           `xml:"Context,attr"`
  Exec    []taskActionExec `xml:"Exec,omitempty"`
}

type taskPrincipals struct {
  XMLName    xml.Name        `xml:"Principals"`
  Principals []taskPrincipal `xml:"Principal,omitempty"`
}

type taskPrincipal struct {
  XMLName  xml.Name `xml:"Principal"`
  ID       string   `xml:"id,attr"`
  UserID   string   `xml:"UserId"`
  RunLevel string   `xml:"RunLevel"`
}

type simpleTask struct {
  XMLName       xml.Name       `xml:"Task"`
  TaskVersion   string         `xml:"version,attr"`
  TaskNamespace string         `xml:"xmlns,attr"`
  Triggers      taskTriggers   `xml:"Triggers"`
  Actions       taskActions    `xml:"Actions"`
  Principals    taskPrincipals `xml:"Principals"`
  Settings      taskSettings   `xml:"Settings"`
}

/*

// newSettings just creates a taskSettings instance with the necessary values + a few dynamic ones
func newSettings(terminate, onDemand, startWhenAvailable bool) *taskSettings {
  return &taskSettings{
    MultipleInstancesPolicy: "IgnoreNew",
    AllowHardTerminate:      terminate,
    IdleSettings: taskIdleSettings{
      StopOnIdleEnd: true,
      RestartOnIdle: false,
    },
    AllowStartOnDemand: onDemand,
    Enabled:            true,
    Hidden:             true,
    Priority:           7, // a pretty standard value for scheduled tasks
    StartWhenAvailable: startWhenAvailable,
  }
}

// newTask creates a task with any static values filled
func newTask(se *taskSettings, pr []taskPrincipal, tr taskTriggers, cmd, args string) *simpleTask {
  if se == nil {
    se = newSettings(true, true, false)
  }
  if pr == nil || len(pr) == 0 {
    pr = []taskPrincipal{
      {
        ID:       "1",
        UserID:   "S-1-5-18",
        RunLevel: "HighestAvailable",
      },
    }
  }
  return &simpleTask{
    TaskVersion:   "1.2",
    TaskNamespace: "http://schemas.microsoft.com/windows/2004/02/mit/task",
    Triggers:      tr,
    Principals:    taskPrincipals{Principals: pr},
    Settings:      *se,
    Actions: taskActions{
      Context: pr[0].ID,
      Exec: []taskActionExec{
        {
          Command:   cmd,
          Arguments: args,
        },
      },
    },
  }
}
*/

// xmlDuration is a *very* simple implementation of xs:duration - only accepts +seconds
func xmlDuration(dur time.Duration) string {
  if s := int(dur.Seconds()); s >= 0 {
    return fmt.Sprintf(`PT%dS`, s)
  }
  return `PT0S`
}

// ValidateTaskName will validate the provided task name according to https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fa8809c8-4f0f-4c6d-994a-6c10308757c1
func ValidateTaskName(taskName string) error {
  if !TaskNameRegex.MatchString(taskName) {
    return fmt.Errorf("invalid task name: %s", taskName)
  }
  return nil
}

// ValidateTaskPath will validate the provided task path according to https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fa8809c8-4f0f-4c6d-994a-6c10308757c1
func ValidateTaskPath(taskPath string) error {
  if !TaskPathRegex.MatchString(taskPath) {
    return fmt.Errorf("invalid task path: %s", taskPath)
  }
  return nil
}
