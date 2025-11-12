package discoverdirectory

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// createDirectorySendHTTPRequestConfig builds the config for directory discovery.
func createDirectorySendHTTPRequestConfig(baseURL, path string, method common.HttpMethod, requestParams common.HttpRequestParams, MaxRedirects int, config *discover.DiscoverDirectoryConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  method,
		Params:  &requestParams,
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       MaxRedirects,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// RunDirectoryDiscovery launches the directory discovery engine with multi-threading support
func RunDirectoryDiscovery(ctx context.Context, config discover.DiscoverDirectoryConfig) (*discover.DiscoverDirectoryReport, error) {
	// Set context
	var cancel context.CancelFunc
	if config.MaxRuntime > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.MaxRuntime)*time.Second)
		defer cancel()
	}

	// Set log
	log := svc1log.FromContext(ctx)
	log.Info("Starting Directory Discovery with multi-threading")

	// Initialize report
	report := discover.DiscoverDirectoryReport{}
	errors := []string{}
	result := discover.DiscoverDirectoryResult{}

	// Gather all paths
	allPaths, err := gatherPaths(config.Paths, config.WordlistType, config.WordlistSize)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return &report, nil
	}
	log.Info("Paths gathered", svc1log.SafeParam("count", len(allPaths)))

	// Parse response codes
	validCodes, err := utils.ParseResponseCodes(config.ResponseCodes)
	if err != nil {
		report.Result = &result
		report.Errors = append(report.Errors, err.Error())
		return &report, nil
	}

	// Check for timeout before starting main processing
	if ctx.Err() != nil {
		report.Result = &result
		report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds before processing started", config.MaxRuntime))
		return &report, nil
	}

	// Initialize targets
	var targets []*discover.DirectoryTargetInfo
	for _, target := range config.Targets {

		// Check if context has expired
		if ctx.Err() != nil {
			// Return partial results collected so far
			result.Targets = targets
			report.Result = &result
			report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during target processing", config.MaxRuntime))
			return &report, nil
		}

		// Initialize target info
		targetInfo := discover.DirectoryTargetInfo{Target: target, BaselineAttempts: []*common.HttpRequestResponse{}}

		// Split target
		baseURL, parsedTargetPath, _, err := requesthelpers.SplitTargetURL(target)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to split target url: %v", err))
			report.Errors = errors
			continue
		}

		// Get baseline size and word count
		// Follow redirects to get the correct baseline size and word count
		baselineRequest, baselineSize, baselineWords, err := baseLine(ctx, baseURL, parsedTargetPath, validCodes, config.MaxRedirectsBaselineRequest, &config)
		if err != nil {
			errors = append(errors, "failed to get baseline body, stopping enumeration")
			report.Errors = errors
			continue
		}
		baselineSizeInt := *baselineSize
		baselineWordsInt := *baselineWords
		targetInfo.BaselineAttempts = append(targetInfo.BaselineAttempts, baselineRequest)
		log.Info("Baseline size", svc1log.SafeParam("size", baselineSizeInt), svc1log.SafeParam("words", baselineWordsInt))

		// Do not follow redirects to get the correct baseline size and word count
		// This is to prevent false positives from remote configurations that dont redirect but give blanket responses on all paths
		// For random baseline, we accept 404s (not found) since the random path should not exist
		randomBaselineValidCodes := make(map[int]bool)
		for code := range validCodes {
			randomBaselineValidCodes[code] = true
		}
		randomBaselineValidCodes[404] = true // Accept 404 for random paths (expected behavior)

		baselineRandomRequest, baselineSizeRandomPath, baselineWordsRandomPath, err := baseLine(ctx, baseURL, "xxxx", randomBaselineValidCodes, 0, &config)
		if err != nil {
			log.Debug("Failed to get baseline random path", svc1log.SafeParam("error", err.Error()))
			// This is not a fatal error - we can continue enumeration without the random baseline
			// The random baseline is just an additional check to reduce false positives
		}
		if baselineSizeRandomPath != nil && baselineWordsRandomPath != nil {
			targetInfo.BaselineAttempts = append(targetInfo.BaselineAttempts, baselineRandomRequest)
			log.Info("Baseline size random path", svc1log.SafeParam("size", *baselineSizeRandomPath), svc1log.SafeParam("words", *baselineWordsRandomPath))
		}

		// Check if context expired during baseline setup
		if ctx.Err() != nil {
			// Return partial results collected so far
			result.Targets = targets
			report.Result = &result
			report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during baseline setup", config.MaxRuntime))
			return &report, nil
		}

		// Multi-threaded request processing
		var attempts []*common.HttpRequestResponse
		var attemptsMutex sync.Mutex
		var wg sync.WaitGroup
		threads := config.Threads
		if threads == 0 {
			threads = runtime.NumCPU()
		}
		semaphore := make(chan struct{}, threads) // Limit concurrent requests

		for _, path := range allPaths {
			// Clean path (ie. /foo/bar/ -> /foo/bar or foo/bar -> /foo/bar)
			cleanPath := strings.Trim(path, "/")
			if cleanPath != "" { // If the path is not empty, add a leading slash else leave it as ""
				cleanPath = fmt.Sprintf("/%s", cleanPath)
			}
			fullPath := fmt.Sprintf("%s%s", parsedTargetPath, cleanPath)

			for i := 0; i <= config.Retries; i++ {
				for _, method := range config.HttpMethods {
					// Check if context has expired
					if ctx.Err() != nil {
						// Wait for any running goroutines to complete before returning partial results
						wg.Wait()
						if len(attempts) > 0 {
							targetInfo.Attempts = attempts
							targets = append(targets, &targetInfo)
						}
						result.Targets = targets
						report.Result = &result
						report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during request processing", config.MaxRuntime))
						return &report, nil
					}

					wg.Add(1)
					go func(fullPath string, method common.HttpMethod) {
						defer wg.Done()

						// Check if context has expired before starting
						if ctx.Err() != nil {
							return
						}

						// Acquire semaphore
						select {
						case semaphore <- struct{}{}:
						case <-ctx.Done():
							return
						}
						defer func() { <-semaphore }()

						// Send request
						requestConfig := createDirectorySendHTTPRequestConfig(baseURL, fullPath, method, common.HttpRequestParams{}, 0, &config)
						httpRequest, err := request.SendRequest(ctx, requestConfig)
						if err != nil {
							// Don't add errors if context was cancelled
							if ctx.Err() == nil {
								errors = append(errors, fmt.Sprintf("failed to send request: %v", err))
							}
							return
						}

						// Check if context has expired after request
						if ctx.Err() != nil {
							return
						}

						// Analyze response
						isValid := AnalyzeResponse(ctx, *httpRequest, validCodes, config.IgnoreBaseContentMatch, baselineSizeInt, baselineWordsInt, baselineSizeRandomPath, baselineWordsRandomPath, config.Threshold)

						if isValid {
							attemptsMutex.Lock()
							attempts = append(attempts, httpRequest)
							attemptsMutex.Unlock()
						}

						if config.Sleep > 0 {
							select {
							case <-time.After(time.Duration(config.Sleep) * time.Second):
							case <-ctx.Done():
								return
							}
						}
					}(fullPath, method)
				}
			}
		}

		// Wait for all goroutines to complete
		wg.Wait()

		// Always add results if we have any, even if context expired
		if len(attempts) > 0 {
			targetInfo.Attempts = attempts
			targets = append(targets, &targetInfo)
		}

		// Check if context expired during processing - still return partial results
		if ctx.Err() != nil {
			result.Targets = targets
			report.Result = &result
			report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during processing, returning partial results", config.MaxRuntime))
			return &report, nil
		}
	}

	result.Targets = targets

	report.Result = &result
	report.Config = &config
	report.Errors = errors
	return &report, nil
}

// AnalyzeResponse checks if the response signifies that directory/file was found based on the response code and the baseline size and word count
func AnalyzeResponse(ctx context.Context, request common.HttpRequestResponse, validCodes map[int]bool, checkBaseContentMatch bool, baselineSize, baselineWords int, baselineSizeRandomPath *int, baselineWordsRandomPath *int, threshold float64) bool {
	log := svc1log.FromContext(ctx)
	if request.Response == nil || request.Response.StatusCode == nil || !validCodes[*request.Response.StatusCode] {
		return false
	}

	bodySize := len(*requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody))
	if bodySize == 0 {
		return false
	}

	wordCount := len(strings.Fields(*requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody)))
	// If the response is similar to the baseline or the baseline random path, then it is not a valid finding
	// This is to prevent false positives from remote configurations that dont redirect but give blanket responses on all paths
	if checkBaseContentMatch {
		if (areSimilar(bodySize, baselineSize, threshold) && areSimilar(wordCount, baselineWords, threshold)) ||
			(baselineSizeRandomPath != nil && baselineWordsRandomPath != nil && areSimilar(bodySize, *baselineSizeRandomPath, threshold) && areSimilar(wordCount, *baselineWordsRandomPath, threshold)) {
			return false
		}
	}
	log.Info("Valid directory/file found", svc1log.SafeParam("url", request.Request.BaseUrl), svc1log.SafeParam("path", request.Request.Path), svc1log.SafeParam("size", bodySize), svc1log.SafeParam("words", wordCount))
	return true
}

// baseLine gets the baseline size and word count of the target to be used for validation of the response
func baseLine(ctx context.Context, baseURL string, path string, validCodes map[int]bool, maxRedirects int, config *discover.DiscoverDirectoryConfig) (*common.HttpRequestResponse, *int, *int, error) {
	// set request config
	requestConfig := createDirectorySendHTTPRequestConfig(baseURL, path, common.HttpMethodGet, common.HttpRequestParams{}, maxRedirects, config)

	// send request
	request, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	// For baseline, we accept any response as long as we get one - even 403, 404, etc.
	// The baseline is used for comparison, so we need content regardless of status code
	if request.Response == nil {
		return nil, nil, nil, errors.New("baseline request failed - no response received")
	}

	bodySize := len(*requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody))
	wordCount := len(strings.Fields(*requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody)))

	return request, &bodySize, &wordCount, nil
}

// gatherPaths gathers all paths from the config
func gatherPaths(paths []string, wordlistType *discover.WordlistType, wordlistSize *discover.WordlistSize) ([]string, error) {
	var allPaths []string

	// Add manual paths
	allPaths = append(allPaths, paths...)

	// Add paths from automatic wordlist selection
	if wordlistType != nil && wordlistSize != nil {
		wordlistPath, err := getWordlistPath(*wordlistType, *wordlistSize)
		if err != nil {
			return nil, err
		}

		wordlistPaths, err := utils.GetEntriesFromTXTFiles([]string{wordlistPath})
		if err != nil {
			return nil, fmt.Errorf("failed to load wordlist %s: %v", wordlistPath, err)
		}
		allPaths = append(allPaths, wordlistPaths...)
	}

	return allPaths, nil
}

// getWordlistPath constructs the path to the appropriate wordlist file
func getWordlistPath(wordlistType discover.WordlistType, wordlistSize discover.WordlistSize) (string, error) {
	// Convert enums to strings
	typeStr := strings.ToLower(string(wordlistType))
	sizeStr := strings.ToLower(string(wordlistSize))

	// Construct filename following the pattern: raft-{size}-{type}-lowercase.txt
	filename := fmt.Sprintf("raft-%s-%s-lowercase.txt", sizeStr, typeStr)

	// Try container path first (for Docker deployment)
	containerPath := fmt.Sprintf("var/conf/discover/directory/%s", filename)
	if _, err := os.Stat(containerPath); err == nil {
		return containerPath, nil
	}

	// Fallback to local development path
	localPath := fmt.Sprintf("configs/discover/directory/%s", filename)
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// If neither path exists, return an error with both attempted paths
	return "", fmt.Errorf("wordlist file not found at %s or %s", containerPath, localPath)
}

// areSimilar is a function that checks if the value is similar to the baseline with a given tolerance
// Examples:
// 0 is exact match
// .50 is 50% difference
// 1.00 is 100% difference
// 2.00 is 200% difference
func areSimilar(value, baseline int, tolerance float64) bool {
	difference := math.Abs(float64(value - baseline))
	percent := difference / float64(baseline)
	return percent <= tolerance
}
