package general

import (
	// Standard
	"context"
	"net/http"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerategeneralfern "github.com/Method-Security/webscan/generated/go/enumerate/general"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createRateLimitRequestConfig(baseURL, path string, config enumerategeneralfern.DetectRateLimitConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodStandard,
		BrowserbaseSecrets: nil,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
	}
}

// PerformGeneralRatelimit performs rate limit detection on target URLs within a specified timespan
func PerformGeneralRatelimit(ctx context.Context, config enumerategeneralfern.DetectRateLimitConfig) *enumerategeneralfern.DetectRateLimitReport {
	// Initialize report
	report := &enumerategeneralfern.DetectRateLimitReport{Config: &config}
	errors := []string{}

	// Calculate the interval between requests based on the timespan
	requestInterval := time.Duration(config.Timespan) * time.Second / time.Duration(config.MaxRequests)

	targets := []*enumerategeneralfern.RateLimitTarget{}
	for _, target := range config.Targets {
		// Initialize target info
		targetInfo := &enumerategeneralfern.RateLimitTarget{Target: target, StartTimestamp: time.Now()}

		// Split target URL into base URL and path
		baseURL, parsedTargetPath, err := requesthelpers.SplitTargetURL(target)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Track if a 200 OK response was previously detected for this target
		var hasSeen200 bool
		for requestNumber := 1; requestNumber <= config.MaxRequests; requestNumber++ {
			// Create Request Config
			requestConfig := createRateLimitRequestConfig(baseURL, parsedTargetPath, config)

			// Send Request
			request, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// Check if rate limit was detected
			if rateLimitDetected(request, hasSeen200) {
				targetInfo.DetectedRequest = &enumerategeneralfern.RateLimitAttempt{
					RequestNumber: requestNumber,
					Request:       request,
				}
				break
			}

			// Mark if a 200 OK response was seen
			if request.Response != nil && request.Response.StatusCode != nil && *request.Response.StatusCode == http.StatusOK {
				hasSeen200 = true
			}

			// Enforce the calculated request interval
			if requestInterval > 0 {
				time.Sleep(requestInterval)
			}
		}

		// Append target info to list
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, targetInfo)
	}

	// Populate and return Report
	report.Targets = targets
	report.Errors = errors
	return report
}

// rateLimitDetected checks if a response explicitly indicates that a request was rate-limited
// or if a 403 response is returned after a 200 response was previously seen.
func rateLimitDetected(request *common.HttpRequestResponse, hasSeen200 bool) bool {
	if request == nil || request.Response == nil {
		return false
	}

	response := request.Response

	// Check status codes
	if response.StatusCode != nil {
		switch *response.StatusCode {
		case http.StatusTooManyRequests:
			return true
		case http.StatusForbidden:
			if hasSeen200 {
				return true
			}
		case http.StatusServiceUnavailable:
			// Some APIs return 503 when rate limited
			return true
		}
	}

	// Check response headers
	if response.ResponseHeaders == nil {
		return false
	}

	// Common rate limit header patterns
	rateLimitHeaders := map[string]func(string) bool{
		"retry-after": func(value string) bool {
			// Check if retry-after has a valid value
			return strings.TrimSpace(value) != ""
		},
		"ratelimit-remaining": func(value string) bool {
			// Check if remaining requests is 0
			return strings.TrimSpace(value) == "0"
		},
		"x-ratelimit-remaining": func(value string) bool {
			return strings.TrimSpace(value) == "0"
		},
		"x-ratelimit-limit": func(value string) bool {
			// If limit is set but remaining is 0, it's rate limited
			return strings.TrimSpace(value) != ""
		},
		"x-ratelimit-reset": func(value string) bool {
			// If reset time is set, it's likely rate limited
			return strings.TrimSpace(value) != ""
		},
	}

	for key, values := range response.ResponseHeaders {
		if len(values) == 0 {
			continue
		}

		keyLower := strings.ToLower(key)
		value := strings.TrimSpace(values[0])

		// Check for exact header matches
		if checkFunc, exists := rateLimitHeaders[keyLower]; exists && checkFunc(value) {
			return true
		}

		// Check for partial matches in header names
		for headerPattern, checkFunc := range rateLimitHeaders {
			if strings.Contains(keyLower, headerPattern) && checkFunc(value) {
				return true
			}
		}
	}

	return false
}
