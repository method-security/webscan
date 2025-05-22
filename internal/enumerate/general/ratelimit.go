package general

import (
	// Standard
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerategeneralfern "github.com/Method-Security/webscan/generated/go/enumerate/general"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createRateLimitRequestConfig(baseURL, path string, config enumerategeneralfern.EnumerateGeneralRateLimitConfig) common.SendHttpRequestConfig {
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

// PerformGeneralRatelimit performs rate limit detection on target URLs within a specified timespan and returns a DetectRateLimitReport.
func PerformGeneralRatelimit(ctx context.Context, config enumerategeneralfern.EnumerateGeneralRateLimitConfig) *enumerategeneralfern.DetectRateLimitReport {
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
			if RateLimitDetected(request, hasSeen200) {
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

// RateLimitDetected checks if a response explicitly indicates that a request was rate-limited or if a 403 response is returned after a 200 response was previously seen.
func RateLimitDetected(request *common.HttpRequestResponse, hasSeen200 bool) bool {
	if request == nil || request.Response == nil {
		return false
	}

	response := request.Response

	// Check status codes first - these are definitive
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

	// If we got a 200 OK, we're not rate limited
	if response.StatusCode != nil && *response.StatusCode == http.StatusOK {
		return false
	}

	// Check response headers
	if response.ResponseHeaders == nil {
		return false
	}

	// Common rate limit header patterns
	rateLimitHeaders := map[string]func(string) bool{
		"retry-after": func(value string) bool {
			// Check if retry-after has a valid number
			value = strings.TrimSpace(value)
			if value == "" {
				return false
			}
			// Try to parse as number
			if _, err := strconv.Atoi(value); err == nil {
				return true
			}
			// Try to parse as HTTP date
			if _, err := time.Parse(time.RFC1123, value); err == nil {
				return true
			}
			return false
		},
		"ratelimit-remaining": func(value string) bool {
			// Check if remaining requests is 0 or negative
			value = strings.TrimSpace(value)
			if value == "" {
				return false
			}
			if remaining, err := strconv.Atoi(value); err == nil {
				return remaining <= 0
			}
			return false
		},
		"x-ratelimit-remaining": func(value string) bool {
			// Check if remaining requests is 0 or negative
			value = strings.TrimSpace(value)
			if value == "" {
				return false
			}
			if remaining, err := strconv.Atoi(value); err == nil {
				return remaining <= 0
			}
			return false
		},
	}

	// Track if we have both limit and remaining headers
	hasRemaining := false
	remainingZero := false

	for key, values := range response.ResponseHeaders {
		if len(values) == 0 {
			continue
		}

		keyLower := strings.ToLower(key)
		value := strings.TrimSpace(values[0])

		// Check for exact header matches
		if checkFunc, exists := rateLimitHeaders[keyLower]; exists {
			if keyLower == "x-ratelimit-remaining" || keyLower == "ratelimit-remaining" {
				hasRemaining = true
				if value == "0" {
					remainingZero = true
				}
			} else if checkFunc(value) {
				return true
			}
		}

		// Check for partial matches in header names
		for headerPattern, checkFunc := range rateLimitHeaders {
			if strings.Contains(keyLower, headerPattern) && checkFunc(value) {
				return true
			}
		}
	}

	// If we have remaining header and it's 0, we're rate limited
	if hasRemaining && remainingZero {
		return true
	}

	// Check response body for common rate limit messages
	if response.ResponseBody != nil {
		body := *requesthelpers.GetResponseBodyStringFromBodyStruct(response.ResponseBody)
		body = strings.ToLower(body)
		rateLimitPhrases := []string{
			"rate limit exceeded",
			"too many requests",
			"request limit exceeded",
			"quota exceeded",
			"try again later",
			"please try again",
		}
		for _, phrase := range rateLimitPhrases {
			if strings.Contains(body, phrase) {
				return true
			}
		}
	}

	return false
}
