package task

import "encoding/xml"

// Settings mirrors the <Settings> element (settingsType).
type Settings struct {
  XMLName xml.Name `xml:"Settings"`

  AllowStartOnDemand              bool                    `xml:"AllowStartOnDemand,omitempty"`
  RestartOnFailure                *RestartOnFailure       `xml:"RestartOnFailure,omitempty"`
  MultipleInstancesPolicy         MultipleInstancesPolicy `xml:"MultipleInstancesPolicy,omitempty"`
  DisallowStartIfOnBatteries      bool                    `xml:"DisallowStartIfOnBatteries,omitempty"`
  StopIfGoingOnBatteries          bool                    `xml:"StopIfGoingOnBatteries,omitempty"`
  AllowHardTerminate              bool                    `xml:"AllowHardTerminate,omitempty"`
  StartWhenAvailable              bool                    `xml:"StartWhenAvailable,omitempty"`
  NetworkProfileName              string                  `xml:"NetworkProfileName,omitempty"`
  RunOnlyIfNetworkAvailable       bool                    `xml:"RunOnlyIfNetworkAvailable,omitempty"`
  WakeToRun                       bool                    `xml:"WakeToRun,omitempty"`
  Enabled                         bool                    `xml:"Enabled,omitempty"`
  Hidden                          bool                    `xml:"Hidden,omitempty"`
  DeleteExpiredTaskAfter          string                  `xml:"DeleteExpiredTaskAfter,omitempty"`
  IdleSettings                    *IdleSettings           `xml:"IdleSettings,omitempty"`
  NetworkSettings                 *NetworkSettings        `xml:"NetworkSettings,omitempty"`
  ExecutionTimeLimit              string                  `xml:"ExecutionTimeLimit,omitempty"`
  Priority                        byte                    `xml:"Priority,omitempty"`
  RunOnlyIfIdle                   bool                    `xml:"RunOnlyIfIdle,omitempty"`
  UseUnifiedSchedulingEngine      bool                    `xml:"UseUnifiedSchedulingEngine,omitempty"`
  DisallowStartOnRemoteAppSession bool                    `xml:"DisallowStartOnRemoteAppSession,omitempty"`
}

// RestartOnFailure corresponds to <RestartOnFailure> (restartType),
// retrying a failed task.
type RestartOnFailure struct {
  XMLName  xml.Name `xml:"RestartOnFailure"`
  Interval string   `xml:"Interval"` // xs:duration (min PT1M, max P31D)
  Count    uint8    `xml:"Count"`    // unsignedByte ≥1
}

// MultipleInstancesPolicy enumerates policies for concurrent task instances.
type MultipleInstancesPolicy string

const (
  Parallel     MultipleInstancesPolicy = "Parallel"
  Queue        MultipleInstancesPolicy = "Queue"
  IgnoreNew    MultipleInstancesPolicy = "IgnoreNew"
  StopExisting MultipleInstancesPolicy = "StopExisting"
)

// IdleSettings corresponds to <IdleSettings> (idleSettingsType),
// controlling idle‐based execution.
type IdleSettings struct {
  XMLName       xml.Name `xml:"IdleSettings"`
  StopOnIdleEnd bool     `xml:"StopOnIdleEnd,omitempty"`
  RestartOnIdle bool     `xml:"RestartOnIdle,omitempty"`
  Duration      string   `xml:"Duration,omitempty"`    // xs:duration (deprecated)
  WaitTimeout   string   `xml:"WaitTimeout,omitempty"` // xs:duration (deprecated)
}

// NetworkSettings corresponds to <NetworkSettings> (networkSettingsType),
// specifying which network profile to await.
type NetworkSettings struct {
  XMLName xml.Name `xml:"NetworkSettings"`
  Name    string   `xml:"Name,omitempty"` // nonEmptyString
  Id      string   `xml:"Id,omitempty"`   // guidType
}
