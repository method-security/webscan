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

	// External
	goquery "github.com/PuerkitoBio/goquery"
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

// PerformAppEnumerateWebPageJsBundles fetches an HTML page, extracts external
// JavaScript bundles, and identifies risky JavaScript APIs and DOM sinks.
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

	pageResponse, err := fetchPage(ctx, target, config, browserbaseSecrets)
	if err != nil {
		errors = append(errors, err.Error())
		return targetResult, errors
	}
	if pageResponse == nil || pageResponse.Response == nil || pageResponse.Response.ResponseBody == nil {
		errors = append(errors, "page request returned an empty response body")
		return targetResult, errors
	}
	if pageResponse.Response.StatusCode == nil || *pageResponse.Response.StatusCode < 200 || *pageResponse.Response.StatusCode >= 300 {
		statusCode := 0
		if pageResponse.Response.StatusCode != nil {
			statusCode = *pageResponse.Response.StatusCode
		}
		errors = append(errors, fmt.Sprintf("page request returned unexpected status code %d", statusCode))
		return targetResult, errors
	}

	htmlBody, err := responseBodyBytes(pageResponse.Response.ResponseBody)
	if err != nil {
		errors = append(errors, fmt.Sprintf("failed to decode page response body: %s", err))
		return targetResult, errors
	}

	pageURL := finalResponseURL(target, pageResponse)
	bundleURLs, err := extractBundleURLs(string(htmlBody), pageURL, target, config)
	if err != nil {
		errors = append(errors, err.Error())
		return targetResult, errors
	}

	bundles := make([]*enumeratewebpagefern.JsBundleDetails, 0, len(bundleURLs))
	successfulBundles := 0
	for _, bundleURL := range bundleURLs {
		if config.MaxBundles >= 0 && successfulBundles >= config.MaxBundles {
			break
		}

		bundle, err := fetchBundle(ctx, bundleURL, config)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to fetch bundle %s: %s", bundleURL, err))
			continue
		}
		successfulBundles++
		bundles = append(bundles, bundle)
	}

	sort.SliceStable(bundles, func(i, j int) bool {
		return bundles[i].Url < bundles[j].Url
	})
	targetResult.Bundles = bundles
	return targetResult, errors
}

func fetchPage(ctx context.Context, target string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*common.HttpRequestResponse, error) {
	return fetchResource(ctx, target, config, config.RequestMethod, config.HeadlessConfig, config.BrowserbaseConfig, browserbaseSecrets)
}

func fetchBundle(ctx context.Context, bundleURL string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig) (*enumeratewebpagefern.JsBundleDetails, error) {
	response, err := fetchResource(ctx, bundleURL, config, common.RequestMethodStandard, nil, nil, nil)
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

	body, err := responseBodyBytes(response.Response.ResponseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	bundle := &enumeratewebpagefern.JsBundleDetails{
		Url:       bundleURL,
		SizeBytes: len(body),
		Functions: findRiskyFunctions(string(body)),
	}
	return bundle, nil
}

func fetchResource(ctx context.Context, target string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*common.HttpRequestResponse, error) {
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
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              requestMethod,
		HeadlessConfig:             headlessConfig,
		BrowserbaseConfig:          browserbaseConfig,
		BrowserbaseSecrets:         browserbaseSecrets,
	}
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)
	return request.SendRequest(ctx, sendConfig)
}

func extractBundleURLs(htmlContent string, pageURL string, target string, config enumeratewebpagefern.EnumerateWebPageJsBundlesConfig) ([]string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML page: %w", err)
	}

	baseURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse page URL %s: %w", pageURL, err)
	}

	seen := make(map[string]struct{})
	bundleURLs := []string{}
	doc.Find("script[src]").Each(func(_ int, selection *goquery.Selection) {
		src, exists := selection.Attr("src")
		if !exists {
			return
		}
		src = strings.TrimSpace(src)
		if src == "" {
			return
		}

		parsedSrc, err := url.Parse(src)
		if err != nil {
			return
		}
		resolved := baseURL.ResolveReference(parsedSrc)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return
		}
		resolved.Fragment = ""
		fullURL := resolved.String()
		if config.IgnoreCrossDomainBundles && !utils.IsHostInScope(target, fullURL) {
			return
		}
		if _, ok := seen[fullURL]; ok {
			return
		}
		seen[fullURL] = struct{}{}
		bundleURLs = append(bundleURLs, fullURL)
	})

	return bundleURLs, nil
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
