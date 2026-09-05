package webpage

import (
	// Standard
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratewebpagefern "github.com/Method-Security/webscan/generated/go/enumerate/webpage"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

type riskyFunctionRule struct {
	functionName string
	category     enumeratewebpagefern.JsBundleRiskCategory
	pattern      *regexp.Regexp
}

var riskyFunctionRules = []riskyFunctionRule{
	{
		functionName: "eval",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDynamicCodeExecution,
		pattern:      regexp.MustCompile(`\beval\s*\(`),
	},
	{
		functionName: "Function",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDynamicCodeExecution,
		pattern:      regexp.MustCompile(`\b(?:new\s+)?Function\s*\(`),
	},
	{
		functionName: "execScript",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDynamicCodeExecution,
		pattern:      regexp.MustCompile(`\b(?:window\.)?execScript\s*\(`),
	},
	{
		functionName: "setTimeout(string)",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDynamicCodeExecution,
		pattern:      regexp.MustCompile(`\bsetTimeout\s*\(\s*[\x22\x27\x60]`),
	},
	{
		functionName: "setInterval(string)",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDynamicCodeExecution,
		pattern:      regexp.MustCompile(`\bsetInterval\s*\(\s*[\x22\x27\x60]`),
	},
	{
		functionName: "document.write/writeln",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDomXssSink,
		pattern:      regexp.MustCompile(`\bdocument\.(?:write|writeln)\s*\(`),
	},
	{
		functionName: "innerHTML",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDomXssSink,
		pattern:      regexp.MustCompile(`\.innerHTML\s*=`),
	},
	{
		functionName: "outerHTML",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDomXssSink,
		pattern:      regexp.MustCompile(`\.outerHTML\s*=`),
	},
	{
		functionName: "insertAdjacentHTML",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDomXssSink,
		pattern:      regexp.MustCompile(`\.insertAdjacentHTML\s*\(`),
	},
	{
		functionName: "srcdoc",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDomXssSink,
		pattern:      regexp.MustCompile(`\.srcdoc\s*=`),
	},
	{
		functionName: "dangerouslySetInnerHTML",
		category:     enumeratewebpagefern.JsBundleRiskCategoryDomXssSink,
		pattern:      regexp.MustCompile(`\bdangerouslySetInnerHTML\b`),
	},
	{
		functionName: "location.assign/replace",
		category:     enumeratewebpagefern.JsBundleRiskCategoryUrlNavigation,
		pattern:      regexp.MustCompile(`\b(?:window\.|document\.)?location\.(?:assign|replace)\s*\(`),
	},
	{
		functionName: "window.open",
		category:     enumeratewebpagefern.JsBundleRiskCategoryUrlNavigation,
		pattern:      regexp.MustCompile(`\bwindow\.open\s*\(`),
	},
	{
		functionName: "postMessage",
		category:     enumeratewebpagefern.JsBundleRiskCategoryCrossWindowMessaging,
		pattern:      regexp.MustCompile(`\bpostMessage\s*\(`),
	},
}

// PerformAppEnumerateWebPageJsBundles fetches JavaScript bundle URLs and
// identifies risky JavaScript APIs and DOM sinks.
func PerformAppEnumerateWebPageJsBundles(ctx context.Context, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) enumeratewebpagefern.EnumerateWebPageJsBundlesReport {
	report := enumeratewebpagefern.EnumerateWebPageJsBundlesReport{
		Config: &config,
		Result: &enumeratewebpagefern.EnumerateWebPageJsBundlesResult{},
	}

	for _, target := range config.Targets {
		targetResult, targetErrors := enumerateTarget(ctx, target, config, browserbaseSecrets)
		report.Result.Targets = append(report.Result.Targets, targetResult)
		for _, targetError := range targetErrors {
			report.Errors = append(report.Errors, fmt.Sprintf("target %s: %s", target, targetError))
		}
	}
	sort.SliceStable(report.Result.Targets, func(i, j int) bool {
		return report.Result.Targets[i].Target < report.Result.Targets[j].Target
	})
	return report
}

func enumerateTarget(ctx context.Context, target string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*enumeratewebpagefern.JsBundleTargetDetails, []string) {
	targetResult := &enumeratewebpagefern.JsBundleTargetDetails{Target: target}
	errors := []string{}

	if config.MaxBundles == 0 {
		return targetResult, errors
	}

	bundle, err := fetchBundle(ctx, target, target, config, browserbaseSecrets)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to fetch bundle %s: %s", target, err))
		return targetResult, errors
	}
	if bundle != nil {
		targetResult.Bundles = []*enumeratewebpagefern.JsBundleDetails{bundle}
	}
	return targetResult, errors
}

func fetchBundle(ctx context.Context, target string, bundleURL string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*enumeratewebpagefern.JsBundleDetails, error) {
	// Bundle redirects are allowed to resolve independently from page redirects.
	// Final bundle inclusion is enforced below by IgnoreCrossDomainBundles.
	response, err := fetchResource(ctx, bundleURL, config, false, config.RequestMethod, config.HeadlessConfig, config.BrowserbaseConfig, browserbaseSecrets)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Response == nil {
		return nil, fmt.Errorf("empty response")
	}

	statusCode := 0
	if response.Response.StatusCode != nil {
		statusCode = *response.Response.StatusCode
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code %d", statusCode)
	}

	finalBundleURL := finalResponseURL(bundleURL, response)
	if config.IgnoreCrossDomainBundles && !utils.IsHostInScope(target, finalBundleURL) {
		return nil, nil
	}

	body, err := responseBodyBytes(response.Response.ResponseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}
	if !isJavaScriptBundleResponse(finalBundleURL, response.Response, body) {
		return nil, fmt.Errorf("response did not look like a JavaScript bundle")
	}

	bundle := &enumeratewebpagefern.JsBundleDetails{
		Url:       finalBundleURL,
		SizeBytes: len(body),
		Functions: findRiskyFunctions(string(body)),
	}
	return bundle, nil
}

func isJavaScriptBundleResponse(bundleURL string, response *common.HttpResponse, body []byte) bool {
	contentType := strings.ToLower(requesthelpers.GetContentTypeFromHeaderMap(response.ResponseHeaders))
	if strings.Contains(contentType, "html") {
		return false
	}
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "ecmascript") {
		return true
	}

	detectedContentType := strings.ToLower(requesthelpers.DetectContentTypeFromBytes(body))
	if strings.Contains(detectedContentType, "html") {
		return false
	}

	parsedURL, err := url.Parse(bundleURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsedURL.Path)
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
}

func fetchResource(ctx context.Context, target string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig, ignoreCrossDomainRedirects bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*common.HttpRequestResponse, error) {
	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %w", target, err)
	}

	httpRequest := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query:   queryParams,
			Headers: requesthelpers.BuildAuthHeaders(config.Headers, config.Cookies),
		},
	}
	sendConfig := common.SendHttpRequestConfig{
		Request:                    &httpRequest,
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: ignoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              requestMethod,
		HeadlessConfig:             headlessConfig,
		BrowserbaseConfig:          browserbaseConfig,
		BrowserbaseSecrets:         browserbaseSecrets,
	}
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)
	return request.SendRequest(ctx, sendConfig)
}

func finalResponseURL(fallback string, response *common.HttpRequestResponse) string {
	if response != nil && response.Response != nil && len(response.Response.RedirectChain) > 0 {
		return response.Response.RedirectChain[len(response.Response.RedirectChain)-1]
	}
	return fallback
}

func responseBodyBytes(body *common.Body) ([]byte, error) {
	if body == nil {
		return []byte{}, nil
	}
	switch body.Kind {
	case "binary":
		if body.Binary == nil {
			return []byte{}, nil
		}
		decoded, err := base64.StdEncoding.DecodeString(body.Binary.Base64)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	case "json":
		if body.Json != nil {
			return []byte(body.Json.Data), nil
		}
	case "text":
		if body.Text != nil {
			return []byte(body.Text.Value), nil
		}
	}
	if value := requesthelpers.GetResponseBodyStringFromBodyStruct(body); value != nil {
		return []byte(*value), nil
	}
	return []byte{}, nil
}

func findRiskyFunctions(content string) []*enumeratewebpagefern.JsBundleFunctionDetails {
	functions := []*enumeratewebpagefern.JsBundleFunctionDetails{}
	seen := make(map[string]struct{})
	for _, rule := range riskyFunctionRules {
		for _, match := range rule.pattern.FindAllStringIndex(content, -1) {
			line, column, snippet := sourceLocation(content, match[0], match[1])
			key := fmt.Sprintf("%s:%d:%d", rule.functionName, line, column)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			functions = append(functions, &enumeratewebpagefern.JsBundleFunctionDetails{
				FunctionName: rule.functionName,
				Category:     rule.category,
				Line:         line,
				Column:       column,
				Snippet:      snippet,
			})
		}
	}
	sortFunctions(functions)
	return functions
}

func sourceLocation(content string, start int, end int) (int, int, string) {
	if start < 0 || end < start || end > len(content) {
		return 0, 0, ""
	}
	prefix := content[:start]
	line := strings.Count(prefix, "\n") + 1
	lineStart := strings.LastIndex(prefix, "\n") + 1
	column := utf8.RuneCountInString(content[lineStart:start]) + 1
	return line, column, contextSnippet(content, start, end)
}

func contextSnippet(content string, start int, end int) string {
	const contextChars = 25

	before := []rune(content[:start])
	match := []rune(content[start:end])
	after := []rune(content[end:])

	beforeStart := max(0, len(before)-contextChars)
	afterEnd := min(contextChars, len(after))
	return string(before[beforeStart:]) + string(match) + string(after[:afterEnd])
}

func sortFunctions(functions []*enumeratewebpagefern.JsBundleFunctionDetails) {
	sort.SliceStable(functions, func(i, j int) bool {
		if functions[i].Line != functions[j].Line {
			return functions[i].Line < functions[j].Line
		}
		if functions[i].Column != functions[j].Column {
			return functions[i].Column < functions[j].Column
		}
		return functions[i].FunctionName < functions[j].FunctionName
	})
}
