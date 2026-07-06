package discoverdirectory

import (
	// Standard
	"context"
	"fmt"
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
	report := discover.DiscoverDirectoryReport{Config: &config}
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

		// Aggregate per-target request failures so we emit one grouped summary per
		// category instead of one error per path (which is noise for large wordlists).
		disallowedStatusCounts := map[int]int{}
		var sendFailureCount int
		var sendFailureSample string

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
						errors = append(errors, groupRequestFailures(baseURL, disallowedStatusCounts, sendFailureCount, sendFailureSample)...)
						if len(attempts) > 0 {
							targetInfo.Attempts = attempts
							targets = append(targets, &targetInfo)
						}
						result.Targets = targets
						errors = append(errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during request processing", config.MaxRuntime))
						report.Result = &result
						report.Errors = errors
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
								attemptsMutex.Lock()
								sendFailureCount++
								if sendFailureSample == "" {
									sendFailureSample = err.Error()
								}
								attemptsMutex.Unlock()
							}
							return
						}

						// Check if context has expired after request
						if ctx.Err() != nil {
							return
						}

						// Analyze response
						isValid, disallowedStatus := AnalyzeResponse(ctx, *httpRequest, validCodes, config.IgnoreBaseContentMatch, config.OmitStandardResponses, baselineSizeInt, baselineWordsInt, baselineSizeRandomPath, baselineWordsRandomPath, config.Threshold)

						if isValid {
							attemptsMutex.Lock()
							attempts = append(attempts, httpRequest)
							attemptsMutex.Unlock()
						} else if disallowedStatus != 0 {
							attemptsMutex.Lock()
							disallowedStatusCounts[disallowedStatus]++
							attemptsMutex.Unlock()
						}

						if config.Sleep > 0 {
							delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
							select {
							case <-time.After(delay):
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

		// Collapse this target's request failures into grouped summaries
		errors = append(errors, groupRequestFailures(baseURL, disallowedStatusCounts, sendFailureCount, sendFailureSample)...)

		// Always add results if we have any, even if context expired
		if len(attempts) > 0 {
			targetInfo.Attempts = attempts
			targets = append(targets, &targetInfo)
		}

		// Check if context expired during processing - still return partial results
		if ctx.Err() != nil {
			result.Targets = targets
			errors = append(errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during processing, returning partial results", config.MaxRuntime))
			report.Result = &result
			report.Errors = errors
			return &report, nil
		}
	}

	result.Targets = targets

	report.Result = &result
	report.Errors = errors
	return &report, nil
}
