package standard

import (
	// Standard
	"context"
	"fmt"
	"io"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"
)

// MaxResponseBodyBytes caps how many bytes any single response body is buffered
// into memory before truncation. Previously SendStandardRequest used
// `io.ReadAll(resp.Body)` without bound, which lets a pathological target — or
// a self-DoS crawl (e.g. wordlist BFS on a site serving multi-GB pages) — pin
// arbitrary memory per request. 50 MiB is well above any legitimate HTML / JS /
// JSON payload while bounding worst-case memory. Callers that genuinely need
// larger payloads should stream rather than buffer.
const MaxResponseBodyBytes int64 = 50 * 1024 * 1024

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
	var rawHeaders map[string][]string
	if request.Params != nil {
		rawHeaders = request.Params.Headers
	}
	constructedHeaders := requesthelpers.FlattenHeaders(rawHeaders)

	// Send Request
	sentAt := time.Now()
	request.SentAt = sentAt
	resp, redirectChain, err := standardhelpers.SendHTTPRequest(ctx, *constructedURL, constructedHeaders, constructedReqReader, config)
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("request failed: %v", err)
	}

	// Marshal Response — bound at MaxResponseBodyBytes to prevent self-DoS on
	// pathologically large responses. The +1 lets us detect that the body
	// exceeded the cap (so we can surface it as an error) without buffering
	// the whole thing.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("failed to read response body: %v", err)
	}
	if int64(len(bodyBytes)) > MaxResponseBodyBytes {
		_ = resp.Body.Close()
		urlStr := ""
		if constructedURL != nil {
			urlStr = *constructedURL
		}
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("response body exceeded MaxResponseBodyBytes=%d (target=%s)", MaxResponseBodyBytes, urlStr)
	}
	response := requesthelpers.CreateHTTPResponseFromBytes(resp.StatusCode, redirectChain, resp.Header, bodyBytes)
	err = resp.Body.Close()
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("failed to close response body: %v", err)
	}

	// Populate the HTTP Request Response struct
	httpRequestResponse := common.HttpRequestResponse{Request: request, Response: &response}
	return httpRequestResponse, nil
}
