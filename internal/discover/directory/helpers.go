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
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
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

// groupRequestFailures collapses a target's per-request failures into grouped summary
// messages (one per send-failure batch, one per rejected status code, and one for bodies
// omitted as standard responses) so large wordlists don't produce one error per path.
// Status codes are sorted for deterministic output.
func groupRequestFailures(baseURL string, disallowedStatusCounts map[int]int, sendFailureCount int, sendFailureSample string, standardResponseCount int) []string {
	var grouped []string
	if sendFailureCount > 0 {
		grouped = append(grouped, fmt.Sprintf("%s: %d request(s) failed to send (e.g. %s)", baseURL, sendFailureCount, sendFailureSample))
	}
	codes := make([]int, 0, len(disallowedStatusCounts))
	for code := range disallowedStatusCounts {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		grouped = append(grouped, fmt.Sprintf("%s: %d path(s) returned status code %d which is not in the allowed response codes", baseURL, disallowedStatusCounts[code], code))
	}
	if standardResponseCount > 0 {
		grouped = append(grouped, fmt.Sprintf("%s: %d path(s) returned an allowed status code but a standard-response body (e.g. soft 404, WAF block, or server error) and were omitted; re-run with --omit-standard-responses=false if you suspect false negatives", baseURL, standardResponseCount))
	}
	return grouped
}

// AnalyzeResponse checks if the response signifies that a directory/file was found based on
// the response code and the baseline size and word count. It returns:
//   - valid: true when the response is a genuine directory/file finding.
//   - disallowedStatus: the response status code when the response was rejected solely
//     because its status code is not in the allowed set (0 otherwise).
//   - standardResponse: true when the response was rejected because its body matched a
//     standard-response fingerprint (soft 404, WAF block, generic server error, etc.).
//
// The disallowedStatus and standardResponse signals let the caller group these rejections
// in the report instead of reporting (or silently dropping) every path individually.
func AnalyzeResponse(ctx context.Context, request common.HttpRequestResponse, validCodes map[int]bool, checkBaseContentMatch bool, omitStandardResponses bool, baselineSize, baselineWords int, baselineSizeRandomPath *int, baselineWordsRandomPath *int, threshold float64) (valid bool, disallowedStatus int, standardResponse bool) {
	log := svc1log.FromContext(ctx)
	if request.Response == nil || request.Response.StatusCode == nil {
		return false, 0, false
	}
	statusCode := *request.Response.StatusCode
	if !validCodes[statusCode] {
		log.Debug("Status code not in allowed response codes",
			svc1log.SafeParam("url", request.Request.BaseUrl),
			svc1log.SafeParam("path", request.Request.Path),
			svc1log.SafeParam("status_code", statusCode))
		return false, statusCode, false
	}

	bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody)
	if bodyStr == nil {
		return false, 0, false
	}
	bodySize := len(*bodyStr)
	if bodySize == 0 {
		return false, 0, false
	}

	// Some servers return a 200 (or another allowed status code) while the body is actually a
	// standard response (e.g. a soft 404 or a WAF rejection). Treat those as not found to
	// reduce false positives.
	if omitStandardResponses && isStandardResponseBody(*bodyStr) {
		log.Info("Allowed status code but body matched a standard response, treating as not found",
			svc1log.SafeParam("url", request.Request.BaseUrl),
			svc1log.SafeParam("path", request.Request.Path))
		return false, 0, true
	}

	wordCount := len(strings.Fields(*bodyStr))
	// If the response is similar to the baseline or the baseline random path, then it is not a valid finding
	// This is to prevent false positives from remote configurations that dont redirect but give blanket responses on all paths
	if checkBaseContentMatch {
		if (areSimilar(bodySize, baselineSize, threshold) && areSimilar(wordCount, baselineWords, threshold)) ||
			(baselineSizeRandomPath != nil && baselineWordsRandomPath != nil && areSimilar(bodySize, *baselineSizeRandomPath, threshold) && areSimilar(wordCount, *baselineWordsRandomPath, threshold)) {
			return false, 0, false
		}
	}
	log.Info("Valid directory/file found", svc1log.SafeParam("url", request.Request.BaseUrl), svc1log.SafeParam("path", request.Request.Path), svc1log.SafeParam("size", bodySize), svc1log.SafeParam("words", wordCount))
	return true, 0, false
}

// standardResponseFingerprints are substrings that commonly appear in the body of standard
// responses (soft 404s, WAF blocks, generic server errors, etc). When any of these are
// present in a response body we should not treat the path as a valid finding, even if the
// status code is in the allowed set.
//
// Matching is done via strings.Contains, so each entry must be the shortest distinctive
// phrase for the response it represents. Do not add longer phrases that already contain one
// of these substrings (e.g. "404 not found" is redundant with "not found").
var standardResponseFingerprints = []string{
	// Missing / not found resource
	"not found",
	"404 error",
	"error 404",
	"404 status code",
	"could not be found",
	"can't be found",
	"couldn't find",
	"does not exist",
	"doesn't exist",
	"no longer exists",
	"no longer available",
	"no such file or directory",
	"nothing found",
	"no results found",
	"nothing matched your search",
	"the page you are looking for",
	"the resource you are looking for",
	"the file you are looking for",
	"this page can't be displayed",
	// Access denied / WAF rejection
	"access denied",
	"403 forbidden",
	"access forbidden",
	"401 unauthorized",
	"permission to access",
	"request blocked",
	"you have been blocked",
	"requested url was rejected",
	"unauthorized activity",
	"unauthorized access",
	"unauthorized request",
	"incident id",
	// Generic server / gateway errors
	"internal server error",
	"bad gateway",
	"service unavailable",
	"gateway timeout",
	"unexpected error",
	"error occurred while processing your request",
	"something went wrong",
	"temporarily unavailable",
	"under maintenance",
}

// isStandardResponseBody reports whether the provided response body matches the fingerprint
// of a standard response (e.g. soft 404, WAF rejection, or generic server error).
func isStandardResponseBody(responseBody string) bool {
	responseBodyLower := strings.ToLower(responseBody)
	for _, fingerprint := range standardResponseFingerprints {
		if strings.Contains(responseBodyLower, fingerprint) {
			return true
		}
	}
	return false
}

// baseLine gets the baseline size and word count of the target to be used for validation of the response
func baseLine(ctx context.Context, baseURL string, path string, validCodes map[int]bool, maxRedirects int, config *discover.DiscoverDirectoryConfig) (*common.HttpRequestResponse, *int, *int, error) {
	// set request config
	requestConfig := createDirectorySendHTTPRequestConfig(ctx, baseURL, path, common.HttpMethodGet, common.HttpRequestParams{}, maxRedirects, config)

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

// gatherPaths gathers all paths from the config
func gatherPaths(paths []string, wordlistType *discover.WordlistType, wordlistSize *discover.WordlistSize) ([]string, error) {
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

	return allPaths, nil
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
