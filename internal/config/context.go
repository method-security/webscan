package config

import "context"

type contextKey string

const (
	proxyConfigKey contextKey = "proxyConfig"
)

// ProxyConfig holds proxy configuration for HTTP requests
type ProxyConfig struct {
	HttpProxy  string
	SocksProxy string
}

// SetProxyConfig stores proxy configuration in the context
func SetProxyConfig(ctx context.Context, httpProxy, socksProxy string) context.Context {
	proxyConfig := &ProxyConfig{
		HttpProxy:  httpProxy,
		SocksProxy: socksProxy,
	}
	return context.WithValue(ctx, proxyConfigKey, proxyConfig)
}

// GetProxyConfig retrieves proxy configuration from the context
func GetProxyConfig(ctx context.Context) *ProxyConfig {
	if proxyConfig, ok := ctx.Value(proxyConfigKey).(*ProxyConfig); ok {
		return proxyConfig
	}
	return &ProxyConfig{}
}
