package goexec

import (
  "fmt"
  "golang.org/x/net/proxy"
  "net"
  "net/url"
)

// Dialer outlines a basic implementation for establishing network connections
type Dialer interface {

  // Dial establishes a network connection (net.Conn) using the provided parameters
  Dial(network string, address string) (connection net.Conn, err error)
}

// ParseProxyURI parses the provided proxy URI spec to a Dialer
func ParseProxyURI(uri string) (dialer Dialer, err error) {

  // Parse proxy spec as URL
  u, err := url.Parse(uri)
  if err != nil {
    return nil, fmt.Errorf("parse proxy URI: %w", err)
  }

  // Create dialer from URL
  dialer, err = proxy.FromURL(u, nil)
  if err != nil {
    return nil, fmt.Errorf("init proxy: %w", err)
  }

  return
}
