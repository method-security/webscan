package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"
)

type KDCDialer interface {
	Dial(network, address string) (net.Conn, error)
}

// Settings holds optional client settings.
type Settings struct {
	disablePAFXFast         bool
	assumePreAuthentication bool
	preAuthEType            int32
	logger                  *log.Logger
	dialer                  KDCDialer
	anyServiceClassSPN      bool
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool
	AssumePreAuthentication bool
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := new(Settings)
	for _, set := range settings {
		set(s)
	}
	return s
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true))
func DisablePAFXFAST(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
func (s *Settings) DisablePAFXFAST() bool {
	return s.disablePAFXFast
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication = b
	}
}

// AnyServiceClassSPN used to configure the client to allow using tickets
// matching target SPN that does not match the service class of the target service.
// Microsoft Services do not require the service class to match the target SPN.
//
// s := NewSettings(AnyServiceClassSPN(true))
func AnyServiceClassSPN(b bool) func(*Settings) {
	return func(s *Settings) {
		s.anyServiceClassSPN = b
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Dialer used to configure client with a custom dialer.
//
// s := NewSettings(&net.Dialer{Timeout: 1 * time.Minute})
func Dialer(d KDCDialer) func(*Settings) {
	return func(s *Settings) {
		s.dialer = d
	}
}

// Dialer returns the client dialer instance.
func (s *Settings) Dialer() KDCDialer {
	if s.dialer != nil {
		return s.dialer
	}
	return &net.Dialer{Timeout: 5 * time.Minute}
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication,
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil

}
