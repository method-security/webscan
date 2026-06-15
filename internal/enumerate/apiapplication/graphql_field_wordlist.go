package apiapplication

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"

	// Configs
	"github.com/Method-Security/webscan/configs"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	defaultFieldWordlistTimeout   = 30
	defaultFieldWordlistBatchSize = 10
	maxFieldWordlistBatchSize     = 50
	defaultParentType             = "Query"
	// defaultWordlistPath is the embedded config path for the GraphQL field wordlist.
	defaultWordlistPath = "enumerate/apiapplication/graphql/fields_default.txt"
)

// validIdentifier matches valid GraphQL identifier names.
var validIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// didYouMeanRegex matches quoted field names inside "Did you mean" suggestions.
var didYouMeanRegex = regexp.MustCompile(`"([^"]+)"`)

// PerformAppEnumerateGraphQLFieldWordlist probes a GraphQL endpoint for accessible
// field names by iterating over a wordlist and parsing "Did you mean" suggestions
// from error responses. This is used as a fallback when introspection is disabled.
//
// Note: non-Query parent type probing is best-effort in this initial version — the
// parentType value is recorded on each confirmed field but the query shape always
// probes at the top-level Query object.
func PerformAppEnumerateGraphQLFieldWordlist(
	ctx context.Context,
	config enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistConfig,
) enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistReport {
	log := svc1log.FromContext(ctx)
	log.Info("Performing GraphQL field wordlist probe", svc1log.SafeParam("target", config.Target))

	report := enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistReport{Config: &config}
	report.Result = &enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistResult{}

	// Resolve effective parent type
	effectiveParentType := defaultParentType
	if config.ParentType != nil && *config.ParentType != "" {
		effectiveParentType = *config.ParentType
	}

	// Resolve effective batch size
	effectiveBatchSize := defaultFieldWordlistBatchSize
	if config.BatchSize != nil && *config.BatchSize > 0 {
		effectiveBatchSize = *config.BatchSize
	}
	if effectiveBatchSize > maxFieldWordlistBatchSize {
		effectiveBatchSize = maxFieldWordlistBatchSize
	}

	// Resolve effective timeout
	effectiveTimeout := defaultFieldWordlistTimeout
	if config.Timeout != nil && *config.Timeout > 0 {
		effectiveTimeout = *config.Timeout
	}

	// Resolve effective verifyTls
	effectiveVerifyTls := false
	if config.VerifyTls != nil {
		effectiveVerifyTls = *config.VerifyTls
	}

	// Resolve effective user agent
	effectiveUserAgent := common.UserAgentPresetRandom
	if config.UserAgent != nil {
		effectiveUserAgent = *config.UserAgent
	}

	// Resolve wordlist
	wordlist := config.Wordlist
	if len(wordlist) == 0 {
		embedded, err := configs.ReadLines(defaultWordlistPath)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to load default wordlist: %v", err))
			report.Result.Data = &enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistData{
				Target:     config.Target,
				ParentType: effectiveParentType,
			}
			return report
		}
		wordlist = embedded
	}

	// Filter and sanitize candidate words
	var candidates []string
	for _, word := range wordlist {
		trimmed := strings.TrimSpace(word)
		if trimmed == "" {
			continue
		}
		if !validIdentifier.MatchString(trimmed) {
			log.Debug("Skipping invalid GraphQL identifier", svc1log.SafeParam("word", trimmed))
			continue
		}
		candidates = append(candidates, trimmed)
	}

	if len(candidates) == 0 {
		report.Errors = append(report.Errors, "wordlist contains no valid GraphQL identifiers after sanitization")
		report.Result.Data = &enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistData{
			Target:     config.Target,
			ParentType: effectiveParentType,
		}
		return report
	}

	// Build combined headers + cookies for HTTP requests
	combinedHeaders := requesthelpers.BuildAuthHeaders(config.Headers, config.Cookies)

	// Track confirmed fields (de-duplicated by field name)
	confirmedByName := make(map[string]*enumerateapiapplicationfern.GraphQlConfirmedField)

	// Process candidates in batches
	for i := 0; i < len(candidates); i += effectiveBatchSize {
		end := i + effectiveBatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batch := candidates[i:end]

		responseBody, statusCode, err := sendGraphQLFieldProbe(ctx, config.Target, batch, combinedHeaders, effectiveTimeout, effectiveVerifyTls, effectiveUserAgent)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("batch %d-%d request failed: %v", i, end-1, err))
			continue
		}

		// Non-200 is not necessarily a hard failure — GraphQL servers may return
		// 400 with a useful errors body. Record the status but continue parsing.
		if statusCode != 200 {
			log.Debug("GraphQL field probe returned non-200 status",
				svc1log.SafeParam("status", statusCode),
				svc1log.SafeParam("batchStart", i))
		}

		suggestions, parseErr := parseGraphQLSuggestions(responseBody)
		if parseErr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("batch %d-%d parse error: %v", i, end-1, parseErr))
			continue
		}

		for fieldName, rawSuggestions := range suggestions {
			if existing, ok := confirmedByName[fieldName]; ok {
				// Merge any new suggestion strings
				existing.Suggestions = mergeStrings(existing.Suggestions, rawSuggestions)
			} else {
				field := &enumerateapiapplicationfern.GraphQlConfirmedField{
					FieldName:   fieldName,
					ParentType:  effectiveParentType,
					Suggestions: rawSuggestions,
				}
				confirmedByName[fieldName] = field
			}
		}
	}

	// Collect confirmed fields into a slice
	confirmedFields := make([]*enumerateapiapplicationfern.GraphQlConfirmedField, 0, len(confirmedByName))
	for _, field := range confirmedByName {
		confirmedFields = append(confirmedFields, field)
	}

	report.Result.Data = &enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistData{
		Target:          config.Target,
		ParentType:      effectiveParentType,
		ConfirmedFields: confirmedFields,
	}
	return report
}

// sendGraphQLFieldProbe builds and sends a single batch probe query.
// It returns the response body string, HTTP status code, and any transport error.
func sendGraphQLFieldProbe(
	ctx context.Context,
	target string,
	words []string,
	headers map[string][]string,
	timeout int,
	verifyTls bool,
	userAgent common.UserAgentPreset,
) (string, int, error) {
	// Build a top-level query with all candidate words as fields.
	// Most GraphQL servers will return "Did you mean X?" errors for unknown fields
	// at Query level, which is what we parse for confirmation.
	queryBody := fmt.Sprintf(`{"query":"{ %s }"}`, strings.Join(words, " "))
	mimeType := "application/json"

	// Merge Content-Type header
	mergedHeaders := make(map[string][]string)
	for k, v := range headers {
		mergedHeaders[k] = v
	}
	mergedHeaders["Content-Type"] = []string{"application/json"}

	baseURL, parsedTargetPath, _, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return "", 0, fmt.Errorf("failed to split target URL: %w", err)
	}

	httpReq := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    parsedTargetPath,
		Method:  common.HttpMethodPost,
		Params: &common.HttpRequestParams{
			Headers: mergedHeaders,
			Body: &common.Body{
				Kind: "json",
				Json: &common.JsonBody{
					Data:     queryBody,
					MimeType: &mimeType,
				},
			},
		},
	}

	sendCfg := common.SendHttpRequestConfig{
		Request:            &httpReq,
		MaxRedirects:       0,
		VerifyTls:          verifyTls,
		Timeout:            timeout,
		UserAgent:          userAgent,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}

	resp, err := request.SendRequest(ctx, sendCfg)
	if err != nil {
		return "", 0, fmt.Errorf("HTTP request failed: %w", err)
	}

	statusCode := 0
	if resp.Response != nil && resp.Response.StatusCode != nil {
		statusCode = *resp.Response.StatusCode
	}

	bodyStr := ""
	if resp.Response != nil && resp.Response.ResponseBody != nil {
		if s := requesthelpers.GetResponseBodyStringFromBodyStruct(resp.Response.ResponseBody); s != nil {
			bodyStr = *s
		}
	}

	return bodyStr, statusCode, nil
}

// graphqlErrorResponse is used to unmarshal the top-level errors from a GraphQL response.
type graphqlErrorResponse struct {
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// parseGraphQLSuggestions parses a GraphQL error response body and returns
// a map of confirmed field names to their raw suggestion strings extracted from
// "Did you mean X?" messages in each error.
func parseGraphQLSuggestions(responseBody string) (map[string][]string, error) {
	if strings.TrimSpace(responseBody) == "" {
		return nil, nil
	}

	var errResp graphqlErrorResponse
	if err := json.Unmarshal([]byte(responseBody), &errResp); err != nil {
		return nil, fmt.Errorf("response is not valid JSON: %w", err)
	}

	// Pattern: "Did you mean" followed by one or more quoted names.
	// Examples:
	//   Cannot query field "xyz" on type "Query". Did you mean "user"?
	//   Did you mean "users", "user", or "viewer"?
	didYouMeanPattern := regexp.MustCompile(`(?i)did you mean (.+?)(\?|$)`)

	confirmed := make(map[string][]string)
	for _, e := range errResp.Errors {
		match := didYouMeanPattern.FindStringSubmatch(e.Message)
		if match == nil {
			continue
		}
		suggestionTail := match[1]
		// Extract every quoted name from the suggestions tail
		quotedMatches := didYouMeanRegex.FindAllStringSubmatch(suggestionTail, -1)
		for _, qm := range quotedMatches {
			fieldName := qm[1]
			if fieldName == "" {
				continue
			}
			confirmed[fieldName] = append(confirmed[fieldName], fieldName)
		}
	}
	return confirmed, nil
}

// mergeStrings appends elements of b into a that are not already present.
func mergeStrings(a, b []string) []string {
	existing := make(map[string]bool, len(a))
	for _, s := range a {
		existing[s] = true
	}
	for _, s := range b {
		if !existing[s] {
			a = append(a, s)
			existing[s] = true
		}
	}
	return a
}
