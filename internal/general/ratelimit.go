package webapplication

import (
	"context"
	"net/http"
	"strings"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	generalfern "github.com/Method-Security/webscan/generated/go/general"
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

// createWebserverRateLimitRequestConfig creates a common request configuration
func createWebserverRateLimitRequestConfig(baseURL, path string, config *generalfern.GeneralRateLimitConfig) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		Timeout:            config.Timeout,
		FollowRedirects:    false,
		MaxRedirects:       nil,
		Insecure:           true,
		RequestMethod:      common.RequestMethodStandard,
		BrowserbaseSecrets: nil,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
	}
}

// PerformGeneralRatelimit performs rate limit detection on target URLs within a specified timespan
func PerformGeneralRatelimit(ctx context.Context, config *generalfern.GeneralRateLimitConfig) *generalfern.GeneralRateLimitReport {
	report := &generalfern.GeneralRateLimitReport{Config: config}
	errors := []string{}

	// Calculate the interval between requests based on the timespan
	requestInterval := time.Duration(config.Timespan) * time.Second / time.Duration(config.MaxRequests)

	targets := []*generalfern.GeneralRateLimitTargetInfo{}
	for _, target := range config.Targets {
		targetInfo := &generalfern.GeneralRateLimitTargetInfo{Target: target, StartTimestamp: time.Now()}

		baseURL, parsedTargetPath, err := utils.SplitTarget(target)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Track if a 200 OK response was previously detected for this target
		var hasSeen200 bool
		for requestNumber := 1; requestNumber <= config.MaxRequests; requestNumber++ {
			requestConfig := createWebserverRateLimitRequestConfig(baseURL, parsedTargetPath, config)
			request, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			if rateLimitDetected(request, hasSeen200) {
				targetInfo.DetectedRequest = &generalfern.GeneralRateLimitAttemptInfo{
					RequestNumber: requestNumber,
					Request:       request,
				}
				break
			}
			// Mark if a 200 OK response was seen
			if request.StatusCode != nil && *request.StatusCode == http.StatusOK {
				hasSeen200 = true
			}
			// Enforce the calculated request interval
			if requestInterval > 0 {
				time.Sleep(requestInterval)
			}
		}
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, targetInfo)
	}
	report.Targets = targets
	report.Errors = errors
	return report
}

// rateLimitDetected checks if a response explicitly indicates that a request was rate-limited
// or if a 403 response is returned after a 200 response was previously seen.
func rateLimitDetected(request *common.RequestInfo, hasSeen200 bool) bool {
	if request == nil {
		return false
	}

	if request.StatusCode != nil && *request.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if request.ResponseHeaders != nil && request.ResponseHeaders["X-Retry-After"] != "" || request.ResponseHeaders["X-RateLimit-Remaining"] == "0" {
		return true
	}

	if request.StatusCode != nil && *request.StatusCode == http.StatusForbidden && hasSeen200 {
		return true
	}

	// Check for specific header names and values
	if request.ResponseHeaders == nil {
		return false
	}
	for key, values := range request.ResponseHeaders {
		if (strings.Contains(key, "Retry-After") && len(values) > 0 && string(values[0]) != "") ||
			(strings.Contains(key, "RateLimit-Remaining") && len(values) > 0 && string(values[0]) == "0") {
			return true
		}
	}

	return false
}
