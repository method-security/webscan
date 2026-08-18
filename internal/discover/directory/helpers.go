package discoverdirectory

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	// Configs
	"github.com/Method-Security/webscan/configs"
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	uuid "github.com/google/uuid"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/time/rate"
)

// createDirectorySendHTTPRequestConfig builds the config for directory discovery.
func createDirectorySendHTTPRequestConfig(ctx context.Context, baseURL, path string, method common.HttpMethod, requestParams common.HttpRequestParams, MaxRedirects int, config *discover.DiscoverDirectoryConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  method,
		Params:  &requestParams,
	}
	sendConfig := common.SendHttpRequestConfig{
		Request:                    &request,
		MaxRedirects:               MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              common.RequestMethodStandard,
		HeadlessConfig:             nil,
		BrowserbaseConfig:          nil,
		BrowserbaseSecrets:         nil,
	}

	// Add proxy settings from context
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)

	return sendConfig
}

func newDirectoryRateLimiter(requestsPerSecond int) *rate.Limiter {
	if requestsPerSecond <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(requestsPerSecond), 1)
}

func waitForDirectoryRateLimit(ctx context.Context, limiter *rate.Limiter) error {
	if limiter == nil {
		return nil
	}
	return limiter.Wait(ctx)
}

type directoryScanMetrics struct {
	disallowedStatusCounts   map[int]int
	sendFailureCount         int
	sendFailureSample        string
	calibrationFailureCount  int
	calibrationFailureSample string
	baselineMatchCount       int
	standardResponseCount    int
	commonResponseCount      int
	commonProfileCount       int
}

func countDisallowedResponses(statusCounts map[int]int) int {
	var total int
	for _, count := range statusCounts {
		total += count
	}
	return total
}

// groupRequestFailures collapses per-request scan metrics into grouped summary
// messages so large wordlists do not produce one signal error per path.
func groupRequestFailures(target string, metrics directoryScanMetrics) []string {
	var grouped []string
	if metrics.sendFailureCount > 0 {
		grouped = append(grouped, fmt.Sprintf("target %s: %d request(s) failed to send; sample error: %s", target, metrics.sendFailureCount, metrics.sendFailureSample))
	}
	if metrics.calibrationFailureCount > 0 {
		grouped = append(grouped, fmt.Sprintf("target %s: %d common-response calibration request(s) failed; sample error: %s", target, metrics.calibrationFailureCount, metrics.calibrationFailureSample))
	}
	codes := make([]int, 0, len(metrics.disallowedStatusCounts))
	for code := range metrics.disallowedStatusCounts {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		grouped = append(grouped, fmt.Sprintf("target %s: %d response(s) returned status code %d outside the allowed response codes and were omitted", target, metrics.disallowedStatusCounts[code], code))
	}
	if metrics.baselineMatchCount > 0 {
		grouped = append(grouped, fmt.Sprintf("target %s: %d response(s) matched the base response size/word profile and were omitted", target, metrics.baselineMatchCount))
	}
	if metrics.standardResponseCount > 0 {
		grouped = append(grouped, fmt.Sprintf("target %s: %d response(s) matched a high-confidence standard response text fingerprint and were omitted", target, metrics.standardResponseCount))
	}
	if metrics.commonResponseCount > 0 {
		grouped = append(grouped, fmt.Sprintf("target %s: %d response(s) matched %d common response body profile(s) learned from calibration or repeated scan responses and were omitted", target, metrics.commonResponseCount, metrics.commonProfileCount))
	}
	return grouped
}

// AnalyzeResponse checks if the response signifies that a directory/file was found based on
// the response code and the baseline size and word count. It returns:
//   - valid: true when the response is a genuine directory/file finding.
//   - disallowedStatus: the response status code when the response was rejected solely
//     because its status code is not in the allowed set (0 otherwise).
//   - baselineMatch: true when the response matched the base response size/word profile.
//   - standardResponseMatch: true when the response body matched a high-confidence
//     soft-404 text fingerprint.
//
// The rejection signals let the caller group these outcomes in the report instead
// of reporting (or silently dropping) every path individually.
func AnalyzeResponse(ctx context.Context, request common.HttpRequestResponse, validCodes map[int]bool, enableCommonResponseFilters bool, baselineSize, baselineWords int, threshold float64) (valid bool, disallowedStatus int, baselineMatch bool, standardResponseMatch bool) {
	log := svc1log.FromContext(ctx)
	if request.Response == nil || request.Response.StatusCode == nil {
		return false, 0, false, false
	}
	statusCode := *request.Response.StatusCode
	if !validCodes[statusCode] {
		log.Debug("Status code not in allowed response codes",
			svc1log.SafeParam("url", request.Request.BaseUrl),
			svc1log.SafeParam("path", request.Request.Path),
			svc1log.SafeParam("status_code", statusCode))
		return false, statusCode, false, false
	}

	bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody)
	if bodyStr == nil {
		return false, 0, false, false
	}
	body := *bodyStr
	bodySize := len(body)
	if bodySize == 0 {
		return false, 0, false, false
	}

	wordCount := len(strings.Fields(body))
	if enableCommonResponseFilters && isHighConfidenceStandardResponseBody(body) {
		log.Debug("Response matched high-confidence standard response fingerprint",
			svc1log.SafeParam("url", request.Request.BaseUrl),
			svc1log.SafeParam("path", request.Request.Path))
		return false, 0, false, true
	}

	// If the response is similar to the base path, then it is not a valid finding.
	// Common responses from random paths and repeated scan responses are handled by
	// commonResponseDetector after this eligibility check.
	if enableCommonResponseFilters {
		if areSimilar(bodySize, baselineSize, threshold) && areSimilar(wordCount, baselineWords, threshold) {
			return false, 0, true, false
		}
	}
	log.Debug("Response eligible for directory finding analysis", svc1log.SafeParam("url", request.Request.BaseUrl), svc1log.SafeParam("path", request.Request.Path), svc1log.SafeParam("size", bodySize), svc1log.SafeParam("words", wordCount))
	return true, 0, false, false
}

// highConfidenceStandardResponseFingerprints are deliberately narrow soft-404
// phrases. Keep these specific enough that they are unlikely to appear in real
// content pages; broad terms like "not found" or "access denied" are too noisy.
var highConfidenceStandardResponseFingerprints = []string{
	"the requested url was not found on this server",
	"the requested resource was not found on this server",
	"the page you are looking for could not be found",
	"the page you requested could not be found",
	"the page you are looking for does not exist",
	"the requested page does not exist",
	"404 page not found",
	"404 - page not found",
	"404: page not found",
}

func isHighConfidenceStandardResponseBody(responseBody string) bool {
	responseBodyLower := strings.ToLower(responseBody)
	for _, fingerprint := range highConfidenceStandardResponseFingerprints {
		if strings.Contains(responseBodyLower, fingerprint) {
			return true
		}
	}
	return false
}

func logDirectoryFindings(ctx context.Context, attempts []*common.HttpRequestResponse) {
	log := svc1log.FromContext(ctx)
	for _, attempt := range attempts {
		if attempt == nil || attempt.Request == nil || attempt.Response == nil {
			continue
		}
		bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(attempt.Response.ResponseBody)
		if bodyStr == nil {
			continue
		}
		log.Info("Valid directory/file found",
			svc1log.SafeParam("url", attempt.Request.BaseUrl),
			svc1log.SafeParam("path", attempt.Request.Path),
			svc1log.SafeParam("size", len(*bodyStr)),
			svc1log.SafeParam("words", len(strings.Fields(*bodyStr))))
	}
}

// baseLine gets the baseline size and word count of the target to be used for validation of the response
func baseLine(ctx context.Context, baseURL string, path string, validCodes map[int]bool, maxRedirects int, config *discover.DiscoverDirectoryConfig, limiter *rate.Limiter) (*common.HttpRequestResponse, *int, *int, error) {
	// set request config
	requestConfig := createDirectorySendHTTPRequestConfig(ctx, baseURL, path, common.HttpMethodGet, common.HttpRequestParams{}, maxRedirects, config)

	if err := waitForDirectoryRateLimit(ctx, limiter); err != nil {
		return nil, nil, nil, err
	}

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

	baseBodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody)
	if baseBodyStr == nil {
		return nil, nil, nil, errors.New("baseline request failed - no response body received")
	}
	bodySize := len(*baseBodyStr)
	wordCount := len(strings.Fields(*baseBodyStr))

	return request, &bodySize, &wordCount, nil
}

// calibrateCommonResponses sends intentionally invalid paths and seeds the common-response
// detector with the resulting body profiles.
func calibrateCommonResponses(ctx context.Context, baseURL, parsedTargetPath string, config *discover.DiscoverDirectoryConfig, detector *commonResponseDetector, limiter *rate.Limiter) ([]*common.HttpRequestResponse, int, string) {
	var attempts []*common.HttpRequestResponse
	var failureCount int
	var failureSample string

	for _, method := range config.HttpMethods {
		for _, probePath := range commonResponseCalibrationPaths(parsedTargetPath) {
			requestConfig := createDirectorySendHTTPRequestConfig(ctx, baseURL, probePath, method, common.HttpRequestParams{}, 0, config)
			if err := waitForDirectoryRateLimit(ctx, limiter); err != nil {
				failureCount++
				if failureSample == "" {
					failureSample = err.Error()
				}
				continue
			}
			httpRequest, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				failureCount++
				if failureSample == "" {
					failureSample = err.Error()
				}
				continue
			}
			attempts = append(attempts, httpRequest)
			detector.Seed(httpRequest)
		}
	}

	return attempts, failureCount, failureSample
}

func commonResponseCalibrationPaths(parsedTargetPath string) []string {
	return []string{
		appendDirectoryPath(parsedTargetPath, fmt.Sprintf("webscan-calibration-%s", uuid.NewString())),
		appendDirectoryPath(parsedTargetPath, fmt.Sprintf("webscan-calibration-%s/", uuid.NewString())),
		appendDirectoryPath(parsedTargetPath, fmt.Sprintf("webscan-calibration-%s.txt", uuid.NewString())),
	}
}

func appendDirectoryPath(basePath, childPath string) string {
	basePath = strings.TrimRight(basePath, "/")
	childPath = strings.TrimLeft(childPath, "/")
	if basePath == "" {
		return "/" + childPath
	}
	return basePath + "/" + childPath
}

// gatherPaths gathers all paths from the config
func gatherPaths(paths []string, wordlistType *discover.WordlistType, wordlistSize *discover.WordlistSize, extensions []string) ([]string, error) {
	var allPaths []string

	// Add manual paths
	allPaths = append(allPaths, paths...)

	// Add paths from automatic wordlist selection
	if wordlistType != nil && wordlistSize != nil {
		embeddedPath := getWordlistEmbeddedPath(*wordlistType, *wordlistSize)

		wordlistPaths, err := configs.ReadLines(embeddedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load embedded wordlist %s: %v", embeddedPath, err)
		}
		allPaths = append(allPaths, wordlistPaths...)
	}

	return applyExtensions(allPaths, extensions), nil
}

// Bare word plus one variant per extension, so a directories wordlist can reach app.js.
func applyExtensions(paths []string, extensions []string) []string {
	normalized := normalizeExtensions(extensions)
	if len(normalized) == 0 {
		return paths
	}

	expanded := make([]string, 0, len(paths)*(len(normalized)+1))
	for _, path := range paths {
		expanded = append(expanded, path)
		trimmed := strings.Trim(path, "/")
		if trimmed == "" {
			continue
		}
		for _, extension := range normalized {
			expanded = append(expanded, trimmed+extension)
		}
	}
	return expanded
}

// normalizeExtensions lowercases, de-duplicates and leading-dots the configured extensions.
func normalizeExtensions(extensions []string) []string {
	seen := map[string]bool{}
	normalized := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		trimmed := strings.ToLower(strings.TrimSpace(extension))
		if trimmed == "" || trimmed == "." {
			continue
		}
		if !strings.HasPrefix(trimmed, ".") {
			trimmed = "." + trimmed
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		normalized = append(normalized, trimmed)
	}
	return normalized
}

// recursionDepth returns how many levels below the target may be swept; 0 disables recursion.
func recursionDepth(config *discover.DiscoverDirectoryConfig) int {
	if config.RecursionDepth == nil || *config.RecursionDepth < 0 {
		return 0
	}
	return *config.RecursionDepth
}

// recursionStatusCodes returns the configured frontier-opening codes, or the default set.
func recursionStatusCodes(config *discover.DiscoverDirectoryConfig) string {
	if config.RecursionStatusCodes == nil || strings.TrimSpace(*config.RecursionStatusCodes) == "" {
		return defaultRecursionStatusCodes
	}
	return *config.RecursionStatusCodes
}

// normalizeFrontierPath collapses the trailing-slash variants of one directory to a single key.
func normalizeFrontierPath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func newDirectoryFrontier(current frontier) *discover.DirectoryFrontier {
	result := &discover.DirectoryFrontier{BasePath: current.basePath, Depth: current.depth}
	if current.discoveredFrom != "" {
		result.DiscoveredFrom = &current.discoveredFrom
	}
	return result
}

// A path already carrying an extension is treated as a file and never descended into.
func isRecursionCandidate(attempt *common.HttpRequestResponse, recursionCodes map[int]bool) bool {
	if attempt == nil || attempt.Request == nil || attempt.Response == nil || attempt.Response.StatusCode == nil {
		return false
	}
	if !recursionCodes[*attempt.Response.StatusCode] {
		return false
	}
	return !pathLooksLikeFile(attempt.Request.Path)
}

// pathLooksLikeFile reports whether the last path segment carries a file extension.
func pathLooksLikeFile(path string) bool {
	segment := path
	if index := strings.LastIndex(segment, "/"); index >= 0 {
		segment = segment[index+1:]
	}
	return strings.Contains(segment, ".")
}

// getWordlistEmbeddedPath returns the embedded config path for a directory wordlist.
func getWordlistEmbeddedPath(wordlistType discover.WordlistType, wordlistSize discover.WordlistSize) string {
	typeStr := strings.ToLower(string(wordlistType))
	sizeStr := strings.ToLower(string(wordlistSize))
	return fmt.Sprintf("discover/directory/raft-%s-%s-lowercase.txt", sizeStr, typeStr)
}

// areSimilar is a function that checks if the value is similar to the baseline with a given tolerance
// Examples:
// 0 is exact match
// .50 is 50% difference
// 1.00 is 100% difference
// 2.00 is 200% difference
func areSimilar(value, baseline int, tolerance float64) bool {
	if baseline == 0 {
		return value == 0
	}
	difference := math.Abs(float64(value - baseline))
	percent := difference / float64(baseline)
	return percent <= tolerance
}
