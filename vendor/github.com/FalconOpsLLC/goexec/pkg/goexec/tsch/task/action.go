package task

import (
  "encoding/xml"
)

// ---------------------------------------------------------------------------
// shared base
// ---------------------------------------------------------------------------

// ActionType is the base for all actions (only carries the optional id attribute).
type ActionType struct {
  XMLName xml.Name `xml:"-"`
  Id      string   `xml:"id,attr,omitempty"`
}

// ---------------------------------------------------------------------------
// Exec
// ---------------------------------------------------------------------------

// ExecAction corresponds to <Exec> (execActionType).
type ExecAction struct {
  XMLName xml.Name `xml:"Exec"`
  ActionType

  // <Command> is the program or script to run.
  Command string `xml:"Command"`
  // <Arguments> are passed to the Command.
  Arguments string `xml:"Arguments,omitempty"`
  // <WorkingDirectory> sets the cwd for the process.
  WorkingDirectory string `xml:"WorkingDirectory,omitempty"`
}

// ---------------------------------------------------------------------------
// ComHandler
// ---------------------------------------------------------------------------

// ComHandlerAction corresponds to <ComHandler> (comHandlerActionType).
type ComHandlerAction struct {
  XMLName xml.Name `xml:"ComHandler"`
  ActionType

  // <ClassId> is the COM class ID (GUID).
  ClassId string `xml:"ClassId"`
  // <Data> is passed into the handler (optional).
  Data string `xml:"Data,omitempty"`
}

// ---------------------------------------------------------------------------
// SendEmail
// ---------------------------------------------------------------------------

// SendEmailAction corresponds to <SendEmail> (sendEmailActionType).
type SendEmailAction struct {
  XMLName xml.Name `xml:"SendEmail"`
  ActionType

  Server  string `xml:"Server"`  // SMTP server
  Subject string `xml:"Subject"` // email subject
  To      string `xml:"To"`      // semicolon‑separated
  Cc      string `xml:"Cc,omitempty"`
  Bcc     string `xml:"Bcc,omitempty"`
  ReplyTo string `xml:"ReplyTo,omitempty"`
  Body    string `xml:"Body,omitempty"`
  // optional named header fields
  HeaderFields *NamedValues `xml:"HeaderFields,omitempty"`
}

// ---------------------------------------------------------------------------
// ShowMessage
// ---------------------------------------------------------------------------

// ShowMessageAction corresponds to <ShowMessage> (showMessageActionType).
type ShowMessageAction struct {
  XMLName xml.Name `xml:"ShowMessage"`
  ActionType

  Title   string `xml:"Title"`   // window title
  Message string `xml:"Message"` // body text
}

// ---------------------------------------------------------------------------
// NamedValues (used by SendEmailAction.HeaderFields)
// ---------------------------------------------------------------------------

// NamedValues holds zero or more <Value name="…">…</Value> entries.
type NamedValues struct {
  XMLName xml.Name     //`xml:"HeaderFields"`
  Value   []NamedValue `xml:"Value"`
}

// NamedValue is one name/value pair.
type NamedValue struct {
  XMLName xml.Name `xml:"Value"`
  Name    string   `xml:"name,attr"`
  Value   string   `xml:",chardata"`
}

// ---------------------------------------------------------------------------
// Actions container
// ---------------------------------------------------------------------------

// Actions corresponds to <Actions> (actionsType).
// It may contain any number of each action type, in any order,
// and carries an optional Context attribute.
type Actions struct {
  XMLName xml.Name `xml:"Actions"`

  // Context="" lets you override the default ("Author").
  Context string `xml:"Context,attr,omitempty"`

  Exec        []ExecAction        `xml:"Exec,omitempty"`
  ComHandler  []ComHandlerAction  `xml:"ComHandler,omitempty"`
  SendEmail   []SendEmailAction   `xml:"SendEmail,omitempty"`
  ShowMessage []ShowMessageAction `xml:"ShowMessage,omitempty"`
}

/*
// ---------------------------------------------------------------------------
// Marshal / Unmarshal helpers
// ---------------------------------------------------------------------------

// MarshalXML satisfies xml.Marshaler.
// It writes out the <Actions> start tag (with optional Context attr),
// then each child action in declaration order, then the end tag.
func (a *Actions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
  // prepare start element
  start.Name.Local = "Actions"
  if a.Context != "" {
    start.Attr = append(start.Attr,
      xml.Attr{Name: xml.Name{Local: "Context"}, Value: a.Context},
    )
  }
  // write <Actions ...>
  if err := e.EncodeToken(start); err != nil {
    return err
  }
  // write children
  for _, act := range a.Exec {
    if err := e.Encode(act); err != nil {
      return err
    }
  }
  for _, act := range a.ComHandler {
    if err := e.Encode(act); err != nil {
      return err
    }
  }
  for _, act := range a.SendEmail {
    if err := e.Encode(act); err != nil {
      return err
    }
  }
  for _, act := range a.ShowMessage {
    if err := e.Encode(act); err != nil {
      return err
    }
  }
  // write </Actions>
  if err := e.EncodeToken(xml.EndElement{Name: start.Name}); err != nil {
    return err
  }
  return e.Flush()
}

// UnmarshalXML satisfies xml.Unmarshaler.
// It reads the <Actions> element (capturing Context attr),
// then loops decoding any Exec, ComHandler, SendEmail, or ShowMessage children.
func (a *Actions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
  // capture Context attribute
  for _, attr := range start.Attr {
    if attr.Name.Local == "Context" {
      a.Context = attr.Value
    }
  }

  // iterate tokens until </Actions>
  for {
    tok, err := d.Token()
    if err != nil {
      return err
    }
    switch t := tok.(type) {
    case xml.StartElement:
      switch t.Name.Local {
      case "Exec":
        var act ExecAction
        if err := d.DecodeElement(&act, &t); err != nil {
          return err
        }
        a.Exec = append(a.Exec, act)

      case "ComHandler":
        var act ComHandlerAction
        if err := d.DecodeElement(&act, &t); err != nil {
          return err
        }
        a.ComHandler = append(a.ComHandler, act)

      case "SendEmail":
        var act SendEmailAction
        if err := d.DecodeElement(&act, &t); err != nil {
          return err
        }
        a.SendEmail = append(a.SendEmail, act)

      case "ShowMessage":
        var act ShowMessageAction
        if err := d.DecodeElement(&act, &t); err != nil {
          return err
        }
        a.ShowMessage = append(a.ShowMessage, act)

      default:
        // skip any unknown elements
        if err := d.Skip(); err != nil {
          return err
        }
      }

    case xml.EndElement:
      if t.Name.Local == start.Name.Local {
        // finished
        return nil
      }
    }
  }
}
*/
