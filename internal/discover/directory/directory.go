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
		report.Errors = append(report.Errors, fmt.Sprintf("directory discovery: failed to gather paths: %v", err))
		return &report, nil
	}
	log.Info("Paths gathered", svc1log.SafeParam("count", len(allPaths)))

	// Parse response codes
	validCodes, err := utils.ParseResponseCodes(config.ResponseCodes)
	if err != nil {
		report.Result = &result
		report.Errors = append(report.Errors, fmt.Sprintf("directory discovery: failed to parse response codes %q: %v", config.ResponseCodes, err))
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
			errors = append(errors, fmt.Sprintf("target %s: failed to split target URL: %v", target, err))
			report.Errors = errors
			continue
		}

		var baselineSizeInt int
		var baselineWordsInt int
		detector := newCommonResponseDetector(config.Threshold)
		var calibrationFailureCount int
		var calibrationFailureSample string
		if config.EnableCommonResponseFilters {
			// Follow redirects to get the correct baseline size and word count.
			baselineRequest, baselineSize, baselineWords, err := baseLine(ctx, baseURL, parsedTargetPath, validCodes, config.MaxRedirectsBaselineRequest, &config)
			if err != nil {
				errors = append(errors, fmt.Sprintf("target %s: failed to get base response profile, skipping enumeration: %v", target, err))
				report.Errors = errors
				continue
			}
			baselineSizeInt = *baselineSize
			baselineWordsInt = *baselineWords
			targetInfo.BaselineAttempts = append(targetInfo.BaselineAttempts, baselineRequest)
			log.Info("Baseline size", svc1log.SafeParam("size", baselineSizeInt), svc1log.SafeParam("words", baselineWordsInt))

			calibrationAttempts, failureCount, failureSample := calibrateCommonResponses(ctx, baseURL, parsedTargetPath, &config, detector)
			targetInfo.BaselineAttempts = append(targetInfo.BaselineAttempts, calibrationAttempts...)
			calibrationFailureCount = failureCount
			calibrationFailureSample = failureSample
			log.Info("Common response calibration complete",
				svc1log.SafeParam("attempts", len(calibrationAttempts)),
				svc1log.SafeParam("failures", failureCount))
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

		// Aggregate per-target scan metrics so we emit one grouped summary per category
		// instead of one error per path.
		metrics := directoryScanMetrics{
			disallowedStatusCounts:   map[int]int{},
			calibrationFailureCount:  calibrationFailureCount,
			calibrationFailureSample: calibrationFailureSample,
		}

		threads := config.Threads
		if threads == 0 {
			threads = runtime.NumCPU()
		}
		semaphore := make(chan struct{}, threads) // Limit concurrent requests
		totalRequests := len(allPaths) * len(config.HttpMethods) * (config.Retries + 1)
		var completedRequests int
		log.Info("Starting target directory requests",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("requestCount", totalRequests),
			svc1log.SafeParam("threads", threads))

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
						if config.EnableCommonResponseFilters {
							attempts = detector.Results()
							metrics.commonResponseCount, metrics.commonProfileCount = detector.Metrics()
						}
						logDirectoryFindings(ctx, attempts)
						errors = append(errors, groupRequestFailures(target, metrics)...)
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
						defer func() {
							attemptsMutex.Lock()
							completedRequests++
							completed := completedRequests
							sendFailures := metrics.sendFailureCount
							baselineMatches := metrics.baselineMatchCount
							standardResponses := metrics.standardResponseCount
							disallowedResponses := countDisallowedResponses(metrics.disallowedStatusCounts)
							positiveFindings := len(attempts)
							attemptsMutex.Unlock()

							if completed%250 == 0 || completed == totalRequests {
								filteredCommonResponses := 0
								if config.EnableCommonResponseFilters {
									filteredCommonResponses, _, positiveFindings = detector.ProgressMetrics()
								}
								log.Info("Directory discovery progress",
									svc1log.SafeParam("completedRequests", completed),
									svc1log.SafeParam("positiveFindings", positiveFindings),
									svc1log.SafeParam("sendFailures", sendFailures),
									svc1log.SafeParam("baselineMatches", baselineMatches),
									svc1log.SafeParam("standardResponses", standardResponses),
									svc1log.SafeParam("disallowedStatusCodes", disallowedResponses),
									svc1log.SafeParam("filteredCommonResponses", filteredCommonResponses))
							}
						}()

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
						requestConfig := createDirectorySendHTTPRequestConfig(ctx, baseURL, fullPath, method, common.HttpRequestParams{}, config.MaxRedirects, &config)
						httpRequest, err := request.SendRequest(ctx, requestConfig)
						if err != nil {
							// Don't add errors if context was cancelled
							if ctx.Err() == nil {
								attemptsMutex.Lock()
								metrics.sendFailureCount++
								if metrics.sendFailureSample == "" {
									metrics.sendFailureSample = err.Error()
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
						isValid, disallowedStatus, baselineMatch, standardResponseMatch := AnalyzeResponse(ctx, *httpRequest, validCodes, config.EnableCommonResponseFilters, baselineSizeInt, baselineWordsInt, config.Threshold)

						if isValid {
							if config.EnableCommonResponseFilters {
								detector.Observe(httpRequest)
							} else {
								attemptsMutex.Lock()
								attempts = append(attempts, httpRequest)
								attemptsMutex.Unlock()
							}
						} else if disallowedStatus != 0 {
							attemptsMutex.Lock()
							metrics.disallowedStatusCounts[disallowedStatus]++
							attemptsMutex.Unlock()
						} else if baselineMatch {
							attemptsMutex.Lock()
							metrics.baselineMatchCount++
							attemptsMutex.Unlock()
						} else if standardResponseMatch {
							attemptsMutex.Lock()
							metrics.standardResponseCount++
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

		if config.EnableCommonResponseFilters {
			attempts = detector.Results()
			metrics.commonResponseCount, metrics.commonProfileCount = detector.Metrics()
		}
		logDirectoryFindings(ctx, attempts)
		log.Info("Directory discovery target complete",
			svc1log.SafeParam("target", target),
			svc1log.SafeParam("completedRequests", completedRequests),
			svc1log.SafeParam("findings", len(attempts)),
			svc1log.SafeParam("filteredCommonResponses", metrics.commonResponseCount),
			svc1log.SafeParam("baselineMatches", metrics.baselineMatchCount),
			svc1log.SafeParam("standardResponses", metrics.standardResponseCount),
			svc1log.SafeParam("disallowedStatusCodes", countDisallowedResponses(metrics.disallowedStatusCounts)),
			svc1log.SafeParam("sendFailures", metrics.sendFailureCount))

		// Collapse this target's scan metrics into grouped summaries
		errors = append(errors, groupRequestFailures(target, metrics)...)

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
