package request

import (
	"context"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/stretchr/testify/require"
)

func TestSendRequestBrowserbaseRejectsProxyConfig(t *testing.T) {
	httpProxy := "http://127.0.0.1:8080"
	_, err := SendRequest(context.Background(), common.SendHttpRequestConfig{
		RequestMethod: common.RequestMethodBrowserbase,
		HttpProxy:     &httpProxy,
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "browserbase capture does not support --http-proxy or --socks-proxy")
}
