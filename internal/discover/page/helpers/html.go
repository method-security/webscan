package discoverpage

import (
	// Standard
	"context"
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func PerformHTMLPageCapture(ctx context.Context, config *common.SendHttpRequestConfig) (*common.HttpRequestResponse, error) {
	log := svc1log.FromContext(ctx)

	// Send request
	httpRequestResponse, err := request.SendRequest(ctx, *config)
	if err != nil {
		log.Error("Failed to send request", svc1log.SafeParam("error", err))
		return nil, err
	}

	// Return response
	return httpRequestResponse, nil
}
