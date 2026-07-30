package goexec

import "context"

// Client represents an application layer network client
type Client interface {

  // Connect establishes a connection to the remote server
  Connect(ctx context.Context) error

  // Close terminates the active connection and frees allocated resources
  Close(ctx context.Context) error
}

// ClientOptions represents configuration options for a Client
type ClientOptions struct {

  // Proxy specifies the URI of the proxy server to route client requests through
  Proxy string `json:"proxy,omitempty" yaml:"proxy,omitempty"`

  // Host specifies the hostname or IP address that the client should connect to
  Host string `json:"host" yaml:"host"`

  // Port specifies the network port on Host that the client will connect to
  Port uint16 `json:"port" yaml:"port"`
}
