package discoverpage

import (
	// Standard
	"context"
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
)

// PerformHTMLPageCapture sends an HTTP request using the provided config and returns the response.
func PerformHTMLPageCapture(ctx context.Context, config *common.SendHttpRequestConfig) (*common.HttpRequestResponse, error) {
	// Send request
	httpRequestResponse, err := request.SendRequest(ctx, *config)
	if err != nil {
		return nil, err
	}

	// Return response
	return httpRequestResponse, nil
}
