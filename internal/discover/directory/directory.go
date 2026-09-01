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

	// Internal
	internalcommon "github.com/Method-Security/webscan/internal/common"
	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/time/rate"
)

// 401/403 are included: a protected directory still proves the directory exists.
const defaultRecursionStatusCodes = "200,301,302,307,308,401,403"

// Safety valve against a server that answers every path with a recursion status.
const maxFrontiersPerTarget = 64

// frontier is a base path queued for its own sweep.
type frontier struct {
	basePath       string
	depth          int
	discoveredFrom string
}

// frontierOutcome carries one frontier's sweep results back to the queue loop.
type frontierOutcome struct {
	baselineAttempts []*common.HttpRequestResponse
	attempts         []*common.HttpRequestResponse
	// Judged on the raw response, because a directory's 403 is not a finding under the default response codes.
	recursionCandidates []*common.HttpRequestResponse
	metrics             directoryScanMetrics
	skipReason          string
	timedOutPhase       string
}

// RunDirectoryDiscovery launches the directory discovery engine with multi-threading support
func RunDirectoryDiscovery(ctx context.Context, config discover.DiscoverDirectoryConfig) (*discover.DiscoverDirectoryReport, error) {
	// Set context
	var cancel context.CancelFunc
	if config.GlobalTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.GlobalTimeout)*time.Second)
		defer cancel()
	}

	// Set log
	log := svc1log.FromContext(ctx)
	log.Info("Starting Directory Discovery with multi-threading")

	// Initialize report
	report := discover.DiscoverDirectoryReport{Config: &config}
	errors := []string{}
	result := discover.DiscoverDirectoryResult{}
	limiter := newDirectoryRateLimiter(config.GlobalRateLimit)

	// Gather all paths
	allPaths, err := gatherPaths(config.Paths, config.WordlistType, config.WordlistSize, config.Extensions, addSlashEnabled(&config))
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

	recursionCodes, err := utils.ParseResponseCodes(recursionStatusCodes(&config))
	if err != nil {
		report.Result = &result
		report.Errors = append(report.Errors, fmt.Sprintf("directory discovery: failed to parse recursion status codes: %v", err))
		return &report, nil
	}
	maxDepth := recursionDepth(&config)

	// Check for timeout before starting main processing
	if ctx.Err() != nil {
		report.Result = &result
		report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds before processing started", config.GlobalTimeout))
		return &report, nil
	}

	// Initialize targets
	var targets []*discover.DirectoryTargetInfo
	for _, target := range config.Targets {

		// Check if context has expired
		if ctx.Err() != nil {
			result.Targets = targets
			report.Result = &result
			report.Errors = append(report.Errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during target processing", config.GlobalTimeout))
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

		queue := []frontier{{basePath: parsedTargetPath, depth: 0}}
		// Keyed on base path so a directory reachable from two parents is only swept once.
		queued := map[string]bool{normalizeFrontierPath(parsedTargetPath): true}
		wafAccumulator := internalcommon.WafDetectionAccumulator{}
		var timedOutPhase string

		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]

			outcome := sweepFrontier(ctx, baseURL, current, allPaths, validCodes, recursionCodes, &config, limiter, &wafAccumulator)
			targetInfo.BaselineAttempts = append(targetInfo.BaselineAttempts, outcome.baselineAttempts...)
			targetInfo.Attempts = append(targetInfo.Attempts, outcome.attempts...)
			targetInfo.Frontiers = append(targetInfo.Frontiers, newDirectoryFrontier(current))
			errors = append(errors, groupRequestFailures(target, outcome.metrics)...)
			if outcome.skipReason != "" {
				errors = append(errors, fmt.Sprintf("target %s: frontier %s: %s", target, current.basePath, outcome.skipReason))
				continue
			}
			if outcome.timedOutPhase != "" {
				timedOutPhase = outcome.timedOutPhase
				break
			}

			if current.depth >= maxDepth {
				continue
			}
			for _, candidate := range outcome.recursionCandidates {
				if len(queued) >= maxFrontiersPerTarget {
					log.Warn("Frontier cap reached, not descending further",
						svc1log.SafeParam("target", target),
						svc1log.SafeParam("cap", maxFrontiersPerTarget))
					break
				}
				childPath := candidate.Request.Path
				if queued[normalizeFrontierPath(childPath)] {
					continue
				}
				queued[normalizeFrontierPath(childPath)] = true
				queue = append(queue, frontier{basePath: childPath, depth: current.depth + 1, discoveredFrom: current.basePath})
			}
			if maxDepth > 0 {
				log.Info("Directory discovery frontier complete",
					svc1log.SafeParam("target", target),
					svc1log.SafeParam("basePath", current.basePath),
					svc1log.SafeParam("depth", current.depth),
					svc1log.SafeParam("findings", len(outcome.attempts)),
					svc1log.SafeParam("queued", len(queue)))
			}
		}

		targetInfo.WafDetection = wafAccumulator.Detection()
		if len(targetInfo.Attempts) > 0 || targetInfo.WafDetection != nil {
			targets = append(targets, &targetInfo)
		}

		if timedOutPhase != "" {
			result.Targets = targets
			errors = append(errors, fmt.Sprintf("directory discovery operation timed out after %d seconds during %s", config.GlobalTimeout, timedOutPhase))
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

// Baseline and calibration re-run per frontier: a subdirectory's 403 profile is not the root's 404 profile.
func sweepFrontier(ctx context.Context, baseURL string, current frontier, allPaths []string, validCodes map[int]bool, recursionCodes map[int]bool, config *discover.DiscoverDirectoryConfig, limiter *rate.Limiter, wafAccumulator *internalcommon.WafDetectionAccumulator) frontierOutcome {
	log := svc1log.FromContext(ctx)
	outcome := frontierOutcome{metrics: directoryScanMetrics{disallowedStatusCounts: map[int]int{}}}

	var baselineSizeInt int
	var baselineWordsInt int
	// A status a random path also returns carries no information at this frontier.
	noisyStatuses := map[int]bool{}
	detector := newCommonResponseDetector(config.Threshold)
	if config.EnableCommonResponseFilters {
		// Follow redirects to get the correct baseline size and word count.
		baselineRequest, baselineSize, baselineWords, err := baseLine(ctx, baseURL, current.basePath, validCodes, config.MaxRedirectsBaselineRequest, config, limiter)
		if err != nil {
			outcome.skipReason = fmt.Sprintf("failed to get base response profile, skipping enumeration: %v", err)
			return outcome
		}
		baselineSizeInt = *baselineSize
		baselineWordsInt = *baselineWords
		outcome.baselineAttempts = append(outcome.baselineAttempts, baselineRequest)
		log.Info("Baseline size", svc1log.SafeParam("size", baselineSizeInt), svc1log.SafeParam("words", baselineWordsInt))

		calibrationAttempts, failureCount, failureSample := calibrateCommonResponses(ctx, baseURL, current.basePath, config, detector, limiter)
		outcome.baselineAttempts = append(outcome.baselineAttempts, calibrationAttempts...)
		noisyStatuses = unanimousDirectoryStatuses(calibrationAttempts)
		outcome.metrics.calibrationFailureCount = failureCount
		outcome.metrics.calibrationFailureSample = failureSample
		log.Info("Common response calibration complete",
			svc1log.SafeParam("attempts", len(calibrationAttempts)),
			svc1log.SafeParam("failures", failureCount))
	}

	// Check if context expired during baseline setup
	if ctx.Err() != nil {
		outcome.timedOutPhase = "baseline setup"
		return outcome
	}

	var attempts []*common.HttpRequestResponse
	var attemptsMutex sync.Mutex
	var wg sync.WaitGroup

	threads := config.Threads
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	semaphore := make(chan struct{}, threads) // Limit concurrent requests
	totalRequests := len(allPaths) * len(config.HttpMethods) * (config.Retries + 1)
	var completedRequests int
	log.Info("Starting frontier directory requests",
		svc1log.SafeParam("baseUrl", baseURL),
		svc1log.SafeParam("basePath", current.basePath),
		svc1log.SafeParam("depth", current.depth),
		svc1log.SafeParam("requestCount", totalRequests),
		svc1log.SafeParam("threads", threads))

	for _, path := range allPaths {
		// Clean path (ie. /foo/bar/ -> /foo/bar or foo/bar -> /foo/bar)
		// TrimLeft, not Trim: a trailing slash is the directory probe and must survive to the wire.
		cleanPath := strings.TrimLeft(path, "/")
		if cleanPath != "" {
			cleanPath = fmt.Sprintf("/%s", cleanPath)
		}
		fullPath := fmt.Sprintf("%s%s", strings.TrimRight(current.basePath, "/"), cleanPath)

		for i := 0; i <= config.Retries; i++ {
			for _, method := range config.HttpMethods {
				// Check if context has expired
				if ctx.Err() != nil {
					wg.Wait()
					if config.EnableCommonResponseFilters {
						attempts = detector.Results()
						outcome.metrics.commonResponseCount, outcome.metrics.commonProfileCount = detector.Metrics()
					}
					logDirectoryFindings(ctx, attempts)
					outcome.attempts = attempts
					appendFindingCandidates(&outcome, attempts, recursionCodes)
					outcome.timedOutPhase = "request processing"
					return outcome
				}

				wg.Add(1)
				go func(fullPath string, method common.HttpMethod) {
					defer wg.Done()
					defer func() {
						attemptsMutex.Lock()
						completedRequests++
						completed := completedRequests
						sendFailures := outcome.metrics.sendFailureCount
						baselineMatches := outcome.metrics.baselineMatchCount
						standardResponses := outcome.metrics.standardResponseCount
						disallowedResponses := countDisallowedResponses(outcome.metrics.disallowedStatusCounts)
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

					if err := waitForDirectoryRateLimit(ctx, limiter); err != nil {
						if ctx.Err() == nil {
							attemptsMutex.Lock()
							outcome.metrics.sendFailureCount++
							if outcome.metrics.sendFailureSample == "" {
								outcome.metrics.sendFailureSample = err.Error()
							}
							attemptsMutex.Unlock()
						}
						return
					}

					// Send request
					requestConfig := createDirectorySendHTTPRequestConfig(ctx, baseURL, fullPath, method, common.HttpRequestParams{}, 0, config)
					httpRequest, err := request.SendRequest(ctx, requestConfig)
					if err != nil {
						// Don't add errors if context was cancelled
						if ctx.Err() == nil {
							attemptsMutex.Lock()
							outcome.metrics.sendFailureCount++
							if outcome.metrics.sendFailureSample == "" {
								outcome.metrics.sendFailureSample = err.Error()
							}
							attemptsMutex.Unlock()
						}
						return
					}

					// Check if context has expired after request
					if ctx.Err() != nil {
						return
					}

					wafAccumulator.Add(httpRequest)

					// Analyze response
					isValid, disallowedStatus, baselineMatch, standardResponseMatch := AnalyzeResponse(ctx, *httpRequest, validCodes, config.EnableCommonResponseFilters, baselineSizeInt, baselineWordsInt, config.Threshold)

					// Judged on status alone when the findings pipeline either never sees this response,
					// or cannot meaningfully judge it: a non-2xx body is boilerplate, not a soft 404.
					outsidePipeline := disallowedStatus != 0 || !isSuccessStatus(statusCodeOf(httpRequest))
					if outsidePipeline && isUnfilteredRecursionCandidate(httpRequest, recursionCodes, noisyStatuses) {
						attemptsMutex.Lock()
						outcome.recursionCandidates = append(outcome.recursionCandidates, httpRequest)
						attemptsMutex.Unlock()
					}

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
						outcome.metrics.disallowedStatusCounts[disallowedStatus]++
						attemptsMutex.Unlock()
					} else if baselineMatch {
						attemptsMutex.Lock()
						outcome.metrics.baselineMatchCount++
						attemptsMutex.Unlock()
					} else if standardResponseMatch {
						attemptsMutex.Lock()
						outcome.metrics.standardResponseCount++
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
		outcome.metrics.commonResponseCount, outcome.metrics.commonProfileCount = detector.Metrics()
	}
	logDirectoryFindings(ctx, attempts)
	log.Info("Directory discovery frontier requests complete",
		svc1log.SafeParam("baseUrl", baseURL),
		svc1log.SafeParam("basePath", current.basePath),
		svc1log.SafeParam("completedRequests", completedRequests),
		svc1log.SafeParam("findings", len(attempts)),
		svc1log.SafeParam("filteredCommonResponses", outcome.metrics.commonResponseCount),
		svc1log.SafeParam("baselineMatches", outcome.metrics.baselineMatchCount),
		svc1log.SafeParam("standardResponses", outcome.metrics.standardResponseCount),
		svc1log.SafeParam("disallowedStatusCodes", countDisallowedResponses(outcome.metrics.disallowedStatusCounts)),
		svc1log.SafeParam("sendFailures", outcome.metrics.sendFailureCount))

	outcome.attempts = attempts
	appendFindingCandidates(&outcome, attempts, recursionCodes)
	if ctx.Err() != nil {
		outcome.timedOutPhase = "processing"
	}
	return outcome
}
