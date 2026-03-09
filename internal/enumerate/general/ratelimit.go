package general

import (
	// Standard
	"context"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerategeneralfern "github.com/Method-Security/webscan/generated/go/enumerate/general"
	waf "github.com/Method-Security/webscan/generated/go/pentest/waf"

	// Internal
	pentestwafdetect "github.com/Method-Security/webscan/internal/pentest/waf/detect"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	standard "github.com/Method-Security/webscan/utils/request/standard"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// getWafFingerprint is a helper function that extracts WAF fingerprints from HTTP response data
func getWafFingerprint(httpResponse *common.HttpResponse) *waf.WafFingerprint {
	if httpResponse == nil {
		return nil
	}

	// Extract response body
	var responseBody *string
	if httpResponse.ResponseBody != nil {
		bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpResponse.ResponseBody)
		responseBody = bodyStr
	}

	// Convert headers from map[string][]string to map[string]string
	var responseHeaders map[string]string
	if httpResponse.ResponseHeaders != nil {
		responseHeaders = make(map[string]string)
		for key, values := range httpResponse.ResponseHeaders {
			if len(values) > 0 {
				responseHeaders[key] = values[0] // Take first value if multiple
			}
		}
	}

	// Get WAF fingerprint
	wafFingerprint := pentestwafdetect.FingerprintApplicationFirewall(responseBody, responseHeaders, httpResponse.StatusCode)

	return wafFingerprint
}

func createRateLimitRequestConfig(baseURL, path string, queryParams map[string]string, config *enumerategeneralfern.EnumerateRateLimitConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query: queryParams,
		},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodStandard,
		BrowserbaseSecrets: nil,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
	}
}

// processTarget handles rate limit detection for a single target
func processTarget(ctx context.Context, target string, config *enumerategeneralfern.EnumerateRateLimitConfig, wg *sync.WaitGroup, results chan<- *enumerategeneralfern.RateLimitTarget, errors chan<- string) {
	defer wg.Done()

	// Get logger from context
	log := svc1log.FromContext(ctx)

	// Initialize target info
	targetInfo := &enumerategeneralfern.RateLimitTarget{Target: target, StartTimestamp: time.Now()}

	// Split target URL into base URL and path
	baseURL, parsedTargetPath, queryParams, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		errors <- err.Error()
		return
	}

	// Determine number of concurrent goroutines - use 1 for sequential timing
	maxGoroutines := runtime.GOMAXPROCS(0) // Default to number of CPUs
	if config.Threads > 0 {
		maxGoroutines = config.Threads
	}

	// Create a semaphore to limit concurrent requests
	semaphore := make(chan struct{}, maxGoroutines)

	// Create channels for request results
	requestResults := make(chan *enumerategeneralfern.RateLimitAttempt, config.MaxRequests)
	requestErrors := make(chan error, config.MaxRequests)

	// Create wait group for request goroutines
	var requestWg sync.WaitGroup

	// Track if a 200 OK response was previously detected for this target
	var hasSeen200 bool
	var mu sync.Mutex // Protect hasSeen200

	// Channel to signal when rate limit is detected
	rateLimitDetected := make(chan bool, 1)

	// Send requests (concurrent or sequential based on maxGoroutines)
requestLoop:
	for requestNumber := 1; requestNumber <= config.MaxRequests; requestNumber++ {
		// Check if rate limit has been detected before sending more requests
		select {
		case <-rateLimitDetected:
			log.Error("Rate limit detected, stopping further requests", svc1log.SafeParam("target", target))
			break requestLoop
		default:
			// Continue with request
		}

		requestWg.Add(1)

		// Acquire semaphore (blocks if maxGoroutines are running)
		semaphore <- struct{}{}

		go func(reqNum int) {
			defer requestWg.Done()
			defer func() { <-semaphore }() // Release semaphore when done

			// Print request number to console
			log.Warn("Sending ratelimit request", svc1log.SafeParam("requestNumber", reqNum), svc1log.SafeParam("target", target))

			// Create Request Config
			requestConfig := createRateLimitRequestConfig(baseURL, parsedTargetPath, queryParams, config)

			// Send lightweight request directly
			httpRequestResponse, err := standard.SendStandardRequest(ctx, requestConfig)
			if err != nil {
				requestErrors <- err
				return
			}

			// Check if rate limit was detected
			mu.Lock()
			currentHasSeen200 := hasSeen200
			if httpRequestResponse.Response != nil && httpRequestResponse.Response.StatusCode != nil && *httpRequestResponse.Response.StatusCode == http.StatusOK {
				hasSeen200 = true
			}
			mu.Unlock()

			if RateLimitDetected(&httpRequestResponse, currentHasSeen200) {
				// Get WAF fingerprint using helper function
				wafFingerprint := getWafFingerprint(httpRequestResponse.Response)

				var provider waf.WafProviderEnum
				if wafFingerprint != nil {
					provider = wafFingerprint.Provider
				} else {
					provider = waf.WafProviderEnumUnknown
				}

				requestResults <- &enumerategeneralfern.RateLimitAttempt{
					RequestNumber: reqNum,
					Request:       &httpRequestResponse,
					Provider:      provider,
					Fingerprint:   wafFingerprint,
				}

				// Signal that rate limit was detected
				select {
				case rateLimitDetected <- true:
				default:
					// Channel already has signal, continue
				}
			}
		}(requestNumber)

		// Enforce the calculated request interval for sequential timing
		time.Sleep(time.Duration(config.Sleep) * time.Second)
	}

	// Wait for all request goroutines to complete
	go func() {
		requestWg.Wait()
		close(requestResults)
		close(requestErrors)
	}()

	// Collect the first rate limit detection (if any)
	select {
	case result := <-requestResults:
		targetInfo.DetectedRequest = result
	case <-time.After(time.Duration(config.Timeout) * time.Second):
		// Timeout waiting for results
	}

	// Collect any errors
	for err := range requestErrors {
		errors <- err.Error()
	}

	// Set end timestamp and send result
	targetInfo.EndTimestamp = time.Now()
	results <- targetInfo
}

// PerformGeneralRatelimit performs rate limit detection on target URLs within a specified timespan and returns a DetectRateLimitReport.
func PerformGeneralRatelimit(ctx context.Context, config *enumerategeneralfern.EnumerateRateLimitConfig) *enumerategeneralfern.EnumerateRateLimitReport {
	// Initialize report
	report := &enumerategeneralfern.EnumerateRateLimitReport{Config: config, Result: &enumerategeneralfern.EnumerateRateLimitResult{}}

	// Create channels for results and errors
	results := make(chan *enumerategeneralfern.RateLimitTarget, len(config.Targets))
	errorsChan := make(chan string, len(config.Targets)*config.MaxRequests)

	// Create wait group for goroutines
	var wg sync.WaitGroup

	// Process each target concurrently
	for _, target := range config.Targets {
		wg.Add(1)
		go processTarget(ctx, target, config, &wg, results, errorsChan)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)
	close(errorsChan)

	// Collect results
	targets := make([]*enumerategeneralfern.RateLimitTarget, 0, len(config.Targets))
	for target := range results {
		targets = append(targets, target)
	}

	// Collect errors
	errors := make([]string, 0)
	for err := range errorsChan {
		errors = append(errors, err)
	}

	// Populate and return Report
	report.Result.Targets = targets
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
		bodyPtr := requesthelpers.GetResponseBodyStringFromBodyStruct(response.ResponseBody)
		if bodyPtr == nil {
			return false
		}
		body := strings.ToLower(*bodyPtr)
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
