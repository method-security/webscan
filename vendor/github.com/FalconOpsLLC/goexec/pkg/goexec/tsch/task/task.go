package task

import "encoding/xml"

// ---------------------------------------------------------------------------
// Task (TaskDefinitionType / <Task> root element)
// ---------------------------------------------------------------------------

// Task represents the root <Task> element (type TaskDefinitionType).
// It pulls together RegistrationInfo, Triggers, Principals, Settings, Actions, and Data.
type Task struct {
  XMLName xml.Name `xml:"Task"`
  Version string   `xml:"version,attr"`         // required
  Xmlns   string   `xml:"xmlns,attr,omitempty"` // e.g. "http://schemas.microsoft.com/windows/2004/02/mit/task"

  RegistrationInfo *RegistrationInfo `xml:"RegistrationInfo,omitempty"`
  Triggers         *Triggers         `xml:"Triggers,omitempty"`
  Principals       *Principals       `xml:"Principals,omitempty"`
  Settings         *Settings         `xml:"Settings,omitempty"`
  Actions          *Actions          `xml:"Actions"` // required
  Data             *Data             `xml:"Data,omitempty"`
}
