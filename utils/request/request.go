package utils

import (
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	headless "github.com/Method-Security/webscan/utils/request/helpers/headless"
	browserbase "github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
	standard "github.com/Method-Security/webscan/utils/request/helpers/standard"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// SendRequest sends a request based on the specified request method
func SendRequest(ctx context.Context, requestConfig common.RequestConfig) (*common.RequestInfo, error) {
	log := svc1log.FromContext(ctx)
	var request common.RequestInfo

	switch requestConfig.RequestMethod {
	// Standard capture
	case common.RequestMethodStandard:
		log.Info("Sending standard request")
		request = standard.StandardCapture(ctx, requestConfig)
		return &request, nil

	// Headless capture
	case common.RequestMethodHeadless:
		log.Info("Sending headless request")
		headless := headless.NewRequester(requestConfig.Timeout, requestConfig.HeadlessConfig)
		captureRequest, err := headless.Request(ctx, requestConfig)
		if err != nil {
			return nil, fmt.Errorf("browser capture failed: %w", err)
		}
		return captureRequest, nil

	// Browserbase capture
	case common.RequestMethodBrowserbase:
		log.Info("Sending browserbase request")
		client := browserbase.NewBrowserbaseClient(requestConfig.BrowserbaseConfig, requestConfig.BrowserbaseSecrets)
		browserbase := browserbase.NewBrowserbaseRequester(ctx, *client, requestConfig.Timeout, requestConfig.HeadlessConfig.MinDomStabalizeTime)
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
