package request

import (
	// Standard
	"context"
	"fmt"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
	browserbase "github.com/Method-Security/webscan/utils/request/headless/browserbase"
	standard "github.com/Method-Security/webscan/utils/request/standard"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// SendRequest sends a request based on the specified request method
func SendRequest(ctx context.Context, config common.SendHttpRequestConfig) (*common.HttpRequestResponse, error) {
	// Set timeout for request
	requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer requestCancel()

	// Get the logger from the context
	log := svc1log.FromContext(ctx)

	switch config.RequestMethod {
	// Standard capture
	case common.RequestMethodStandard:
		log.Info("Sending standard request")
		httpRequestResponse, err := standard.SendStandardRequest(requestCtx, config)
		if err != nil {
			return nil, fmt.Errorf("standard capture failed: %w", err)
		}
		return &httpRequestResponse, nil

	// Headless capture
	case common.RequestMethodHeadless:
		log.Info("Sending headless request")
		headless := headless.NewRequester(config.Timeout, config.HeadlessConfig)
		httpRequestResponse, err := headless.SendRequest(requestCtx, config)
		if err != nil {
			return nil, fmt.Errorf("browser capture failed: %w", err)
		}
		return &httpRequestResponse, nil

	// Browserbase capture
	case common.RequestMethodBrowserbase:
		log.Info("Sending browserbase request")
		client := browserbase.NewBrowserbaseClient(config.BrowserbaseConfig, config.BrowserbaseSecrets)
		browserbase := browserbase.NewBrowserbaseRequester(ctx, *client, config.Timeout, config.HeadlessConfig.MinDomStabalizeTime)
		if browserbase == nil {
			return nil, fmt.Errorf("failed to create browserbase capturer")
		}
		httpRequestResponse, err := browserbase.SendRequest(requestCtx, config)
		if err != nil {
			return nil, fmt.Errorf("browserbase capture failed: %w", err)
		}
		return &httpRequestResponse, nil

	// Unsupported request method
	default:
		return nil, fmt.Errorf("invalid request method: %s", config.RequestMethod)
	}
}
