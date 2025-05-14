package utils

import (
	"context"
	"fmt"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils/request/helpers/headless"
	"github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
	standard "github.com/Method-Security/webscan/utils/request/helpers/standard"
)

// SendRequest sends a request based on the specified request method
func SendRequest(ctx context.Context, requestConfig common.RequestConfig) (*common.RequestInfo, error) {
	var request common.RequestInfo

	switch requestConfig.RequestMethod {
	// Standard capture
	case common.RequestMethodStandard:
		request = standard.StandardCapture(requestConfig)
		return &request, nil

	// Headless capture
	case common.RequestMethodHeadless:
		headless := headless.NewRequester(requestConfig.HeadlessConfig, requestConfig.Timeout)
		captureRequest, err := headless.Request(ctx, requestConfig)
		if err != nil {
			return nil, fmt.Errorf("browser capture failed: %w", err)
		}
		return captureRequest, nil

	// Browserbase capture
	case common.RequestMethodBrowserbase:
		client := browserbase.NewBrowserbaseClient(requestConfig.BrowserbaseConfig, requestConfig.BrowserbaseSecrets)
		browserbase := browserbase.NewBrowserbaseRequester(ctx, requestConfig.Timeout, requestConfig.HeadlessConfig.MinDomStabalizeTime, *client)
		if browserbase == nil {
			return nil, fmt.Errorf("failed to create browserbase capturer")
		}
		captureRequest, err := browserbase.Request(ctx, requestConfig)
		if err != nil {
			return nil, fmt.Errorf("browserbase capture failed: %w", err)
		}
		return captureRequest, nil

	default:
		return nil, fmt.Errorf("invalid request method: %s", requestConfig.RequestMethod)
	}
}
