package standard

import (
	// Standard
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"
)

// SendStandardRequest performs an HTTP request using http/net and returns detailed information including response data
func SendStandardRequest(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, error) {
	// Set the request
	request := config.Request
	if request == nil {
		return common.HttpRequestResponse{}, fmt.Errorf("request is nil")
	}

	// Prepare Request
	constructedURL, err := standardhelpers.ConstructURL(ctx, request)
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("URL construction failed: %v", err)
	}
	constructedReqReader, err := standardhelpers.PrepareRequestBody(ctx, request)
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("request body preparation failed: %v", err)
	}
	constructedHeaders := make(map[string]string)
	if request.Params != nil && request.Params.Headers != nil {
		for k, v := range request.Params.Headers {
			if len(v) > 0 {
				constructedHeaders[k] = strings.Join(v, ",")
			}
		}
	}

	// Send Request
	sentAt := time.Now()
	request.SentAt = sentAt
	resp, redirectChain, err := standardhelpers.SendHTTPRequest(ctx, *constructedURL, constructedHeaders, constructedReqReader, config)
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("request failed: %v", err)
	}

	// Marshal Response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("failed to read response body: %v", err)
	}
	bodyStr := string(bodyBytes)
	response := requesthelpers.CreateHTTPResponse(resp.StatusCode, redirectChain, resp.Header, bodyStr)
	err = resp.Body.Close()
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("failed to close response body: %v", err)
	}

	// Populate the HTTP Request Response struct
	httpRequestResponse := common.HttpRequestResponse{Request: request, Response: &response}
	return httpRequestResponse, nil
}
