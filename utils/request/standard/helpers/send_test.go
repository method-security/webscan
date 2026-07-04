package standard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/stretchr/testify/require"
)

func TestSendHTTPRequestUsesHTTPProxy(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusTeapot)
	}))
	defer target.Close()

	proxyHit := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit = true
		require.Equal(t, target.URL+"/", r.URL.String())
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	config := common.SendHttpRequestConfig{
		Request: &common.HttpRequest{
			Method: common.HttpMethodGet,
		},
		VerifyTls:    true,
		Timeout:      5,
		MaxRedirects: 0,
		HttpProxy:    &proxy.URL,
		UserAgent:    common.UserAgentPresetCurl,
	}

	resp, redirectChain, err := SendHTTPRequest(context.Background(), target.URL, nil, nil, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, proxyHit)
	require.False(t, targetHit)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Equal(t, []string{target.URL}, redirectChain)
	require.Equal(t, "proxied", string(body))
}

func TestSendHTTPRequestUsesHTTPProxyWhenBothProxiesAreSet(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusTeapot)
	}))
	defer target.Close()

	proxyHit := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit = true
		require.Equal(t, target.URL+"/", r.URL.String())
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	socksProxy := "socks5://127.0.0.1:1"
	config := common.SendHttpRequestConfig{
		Request: &common.HttpRequest{
			Method: common.HttpMethodGet,
		},
		VerifyTls:    true,
		Timeout:      5,
		MaxRedirects: 0,
		HttpProxy:    &proxy.URL,
		SocksProxy:   &socksProxy,
		UserAgent:    common.UserAgentPresetCurl,
	}

	resp, redirectChain, err := SendHTTPRequest(context.Background(), target.URL, nil, nil, config)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, proxyHit)
	require.False(t, targetHit)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Equal(t, []string{target.URL}, redirectChain)
	require.Equal(t, "proxied", string(body))
}
