package request

import (
	"context"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	appconfig "github.com/Method-Security/webscan/internal/config"
	"github.com/stretchr/testify/require"
)

func TestApplyProxySettingsUsesHTTPProxyFirst(t *testing.T) {
	httpProxy := "http://127.0.0.1:8080"
	socksProxy := "socks5://127.0.0.1:1080"
	ctx := appconfig.SetProxyConfig(context.Background(), httpProxy, socksProxy)
	config := common.SendHttpRequestConfig{}

	ApplyProxySettings(ctx, &config)

	require.NotNil(t, config.HttpProxy)
	require.Equal(t, httpProxy, *config.HttpProxy)
	require.Nil(t, config.SocksProxy)
}

func TestApplyProxySettingsUsesSocksProxyWhenHTTPProxyUnset(t *testing.T) {
	socksProxy := "socks5://127.0.0.1:1080"
	ctx := appconfig.SetProxyConfig(context.Background(), "", socksProxy)
	config := common.SendHttpRequestConfig{}

	ApplyProxySettings(ctx, &config)

	require.Nil(t, config.HttpProxy)
	require.NotNil(t, config.SocksProxy)
	require.Equal(t, socksProxy, *config.SocksProxy)
}
