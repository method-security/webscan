package headless

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/stretchr/testify/require"
)

func TestRequesterProxyServerUsesHTTPProxyFirst(t *testing.T) {
	httpProxy := "http://127.0.0.1:8080"
	socksProxy := "socks5://127.0.0.1:1080"
	requester := NewRequester(5, &common.HeadlessRequestConfig{})
	requester.SetProxyConfigFromRequest(common.SendHttpRequestConfig{
		HttpProxy:  &httpProxy,
		SocksProxy: &socksProxy,
	})

	require.Equal(t, httpProxy, requester.proxyServer())
}

func TestRequesterProxyServerUsesSocksProxyWhenHTTPProxyUnset(t *testing.T) {
	socksProxy := "socks5://127.0.0.1:1080"
	requester := NewRequester(5, &common.HeadlessRequestConfig{})
	requester.SetProxyConfigFromRequest(common.SendHttpRequestConfig{
		SocksProxy: &socksProxy,
	})

	require.Equal(t, socksProxy, requester.proxyServer())
}
