package request

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	appconfig "github.com/Method-Security/webscan/internal/config"
)

// ApplyProxySettings extracts proxy configuration from context and applies it to the request config
func ApplyProxySettings(ctx context.Context, config *common.SendHttpRequestConfig) {
	proxyConfig := appconfig.GetProxyConfig(ctx)
	if proxyConfig.HttpProxy != "" {
		config.HttpProxy = &proxyConfig.HttpProxy
	}
	if proxyConfig.SocksProxy != "" {
		config.SocksProxy = &proxyConfig.SocksProxy
	}
}
