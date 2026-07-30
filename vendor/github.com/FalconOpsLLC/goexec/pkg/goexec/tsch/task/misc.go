package task

import "encoding/xml"

// ---------------------------------------------------------------------------
// RegistrationInfo (registrationInfoType)
// ---------------------------------------------------------------------------

// NamedValuePair represents one <Identification name="…" value="…"/>
// entry within RegistrationInfo.
type NamedValuePair struct {
  XMLName xml.Name `xml:"Identification"`
  Name    string   `xml:"name,attr"`
  Value   string   `xml:"value,attr"`
}

// RegistrationInfo corresponds to the <RegistrationInfo> element.
//
// Fields are all optional and appear in the same order as in the XSD.
type RegistrationInfo struct {
  XMLName xml.Name `xml:"RegistrationInfo"`

  Date               string           `xml:"Date,omitempty"`               // xs:dateTime
  Author             string           `xml:"Author,omitempty"`             // xs:string
  Description        string           `xml:"Description,omitempty"`        // xs:string
  URI                string           `xml:"URI,omitempty"`                // xs:string
  Version            string           `xml:"Version,omitempty"`            // xs:string
  Source             string           `xml:"Source,omitempty"`             // xs:string
  Documentation      string           `xml:"Documentation,omitempty"`      // xs:string
  SecurityDescriptor string           `xml:"SecurityDescriptor,omitempty"` // xs:string (SDDL)
  Identification     []NamedValuePair `xml:"Identification,omitempty"`     // zero or more
}

// ---------------------------------------------------------------------------
// Data (dataType)
// ---------------------------------------------------------------------------

// Data corresponds to the <Data> element under a TaskDefinition.
// It can contain any well‑formed XML inside.
type Data struct {
  XMLName  xml.Name `xml:"Data"`
  InnerXML string   `xml:",innerxml"`
}

// ---------------------------------------------------------------------------
// Principal (principalType)
// ---------------------------------------------------------------------------

// RunLevelType enumerates the RunLevel element values.
type RunLevelType string

const (
  RunLevelLeastPrivilege   RunLevelType = "LeastPrivilege"
  RunLevelHighestAvailable RunLevelType = "HighestAvailable"
)

// LogonType enumerates the LogonType element values.
type LogonType string

const (
  LogonTypeNone             LogonType = "None"
  LogonTypePassword         LogonType = "Password"
  LogonTypeInteractiveToken LogonType = "InteractiveToken"
  LogonTypeS4U              LogonType = "S4U"
  LogonTypeVirtualAccount   LogonType = "VirtualAccount"
  LogonTypeGroup            LogonType = "Group"
)

// ---------------------------------------------------------------------------
// Principals container (principalsType)
// ---------------------------------------------------------------------------

// Principals corresponds to the <Principals> element.
// It holds one or more <Principal> entries.
type Principals struct {
  XMLName   xml.Name    `xml:"Principals"`
  Principal []Principal `xml:"Principal"`
}

// Principal corresponds to the <Principal> element within <Principals>.
type Principal struct {
  XMLName xml.Name `xml:"Principal"`
  Id      string   `xml:"id,attr,omitempty"`

  UserId      string       `xml:"UserId,omitempty"`      // xs:string
  GroupId     string       `xml:"GroupId,omitempty"`     // xs:string
  RunLevel    RunLevelType `xml:"RunLevel,omitempty"`    // default="LeastPrivilege"
  LogonType   LogonType    `xml:"LogonType,omitempty"`   // default="InteractiveToken"
  DisplayName string       `xml:"DisplayName,omitempty"` // xs:string
}
