package enumeratejavascript

import (
	// Standard
	"context"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/enumerate"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// Internal
	javascripthelpers "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// artifact is one fetched JavaScript body plus the record kept about it.
type artifact struct {
	details *enumerate.JavascriptArtifact
	source  []byte
}

// PerformJavascriptEnumeration analyzes a JavaScript bundle and the chunks it declares, returning an
// EnumerateJavascriptReport.
func PerformJavascriptEnumeration(ctx context.Context, config enumerate.EnumerateJavascriptConfig) enumerate.EnumerateJavascriptReport {
	log := svc1log.FromContext(ctx)

	report := enumerate.EnumerateJavascriptReport{
		Config: &config,
		Result: &enumerate.EnumerateJavascriptResult{
			Targets: config.Targets,
		},
	}
	errors := []string{}

	// An application splits what this tool needs across bundles — the API base in one, the chunk
	// manifest in another, the calls in the chunks — so every target is analyzed as one application.
	artifacts := []*artifact{}
	fetched := map[string]struct{}{}
	remaining := config.MaxArtifacts

	for _, target := range config.Targets {
		if _, seen := fetched[target]; seen {
			continue
		}
		fetched[target] = struct{}{}

		entry, err := fetchArtifact(ctx, config, target, enumerate.JavascriptArtifactKindEntry, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		artifacts = append(artifacts, entry)

		if !config.FollowChunks {
			continue
		}
		log.Info("Expanding declared chunks", svc1log.SafeParam("target", target))
		chunks, chunkErrors := fetchDeclaredChunks(ctx, config, entry, fetched, &remaining)
		artifacts = append(artifacts, chunks...)
		errors = append(errors, chunkErrors...)
	}

	if len(artifacts) == 0 {
		report.Errors = append(report.Errors, errors...)
		return report
	}

	if config.FetchSourceMaps {
		maps, mapErrors := fetchSourceMaps(ctx, config, artifacts)
		artifacts = append(artifacts, maps...)
		errors = append(errors, mapErrors...)
	}

	endpoints := []*enumerate.JavascriptEndpoint{}
	secrets := []*enumerate.JavascriptSecret{}
	origins := map[string]struct{}{}

	for _, current := range artifacts {
		analysis := javascripthelpers.AnalyzeSource(current.source, current.details.Url, config.AnalysisWindowBytes, config.AnalysisWindowOverlapBytes)
		current.details.Analyzed = true
		endpoints = append(endpoints, analysis.Endpoints...)
		secrets = append(secrets, analysis.Secrets...)
		for _, origin := range analysis.Origins {
			origins[origin] = struct{}{}
		}
	}

	hosts := targetHosts(config.Targets)
	baseCandidates := javascripthelpers.BaseCandidatesInScope(sortedSet(origins), hosts, config.IgnoreCrossDomainEndpoints)
	endpoints = javascripthelpers.RootEndpoints(dedupeEndpoints(endpoints), baseCandidates, hosts)

	report.Result.Artifacts = artifactDetails(artifacts)
	report.Result.BaseUrlCandidates = baseCandidates
	report.Result.Endpoints = endpoints
	report.Result.Secrets = dedupeSecrets(secrets)
	report.Errors = append(report.Errors, errors...)
	return report
}

// fetchDeclaredChunks resolves the chunk names a bundle's runtime declares and fetches each.
func fetchDeclaredChunks(ctx context.Context, config enumerate.EnumerateJavascriptConfig, entry *artifact, fetched map[string]struct{}, remaining *int) ([]*artifact, []string) {
	source := string(entry.source)
	names := javascripthelpers.ExtractWebpackChunkNames(source)
	if len(names) == 0 {
		names = javascripthelpers.ExtractViteChunkNames(source)
	}
	if len(names) == 0 {
		return nil, nil
	}

	publicPath := javascripthelpers.ExtractPublicPath(source)
	errors := []string{}

	// Resolve first so the budget and the already-fetched set are applied to real URLs.
	type chunk struct {
		name string
		url  string
	}
	declared := len(names)
	pending := make([]chunk, 0, len(names))
	for _, name := range names {
		chunkURL, err := resolveChunkURL(entry.details.Url, publicPath, name)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if _, seen := fetched[chunkURL]; seen {
			continue
		}
		fetched[chunkURL] = struct{}{}
		pending = append(pending, chunk{name: name, url: chunkURL})
	}

	if config.MaxArtifacts > 0 {
		if *remaining <= 0 {
			return nil, append(errors, fmt.Sprintf("skipped %d declared chunks: max-artifacts reached", len(pending)))
		}
		if len(pending) > *remaining {
			errors = append(errors, fmt.Sprintf("fetching %d of %d declared chunks: max-artifacts reached", *remaining, declared))
			pending = pending[:*remaining]
		}
		*remaining -= len(pending)
	}

	// Indexed rather than appended: chunks complete out of order but the report must not.
	results := make([]*artifact, len(pending))
	failures := make([]string, len(pending))

	maxConcurrent := runtime.GOMAXPROCS(0)
	if config.Threads > 0 {
		maxConcurrent = config.Threads
	}
	semaphore := make(chan struct{}, maxConcurrent)

	var waitGroup sync.WaitGroup
	for index, item := range pending {
		waitGroup.Add(1)
		semaphore <- struct{}{}

		go func(index int, item chunk) {
			defer waitGroup.Done()
			defer func() { <-semaphore }()

			applyStealthDelay(ctx, config)

			fetchedChunk, err := fetchArtifact(ctx, config, item.url, enumerate.JavascriptArtifactKindChunk, &entry.details.Url)
			if err != nil {
				failures[index] = err.Error()
				return
			}
			results[index] = fetchedChunk
		}(index, item)
	}
	waitGroup.Wait()

	artifacts := make([]*artifact, 0, len(pending))
	for index := range pending {
		if results[index] != nil {
			artifacts = append(artifacts, results[index])
		}
		if failures[index] != "" {
			errors = append(errors, failures[index])
		}
	}
	return artifacts, errors
}

// applyStealthDelay spaces requests out when a sleep is configured.
func applyStealthDelay(ctx context.Context, config enumerate.EnumerateJavascriptConfig) {
	if config.Sleep <= 0 {
		return
	}
	select {
	case <-time.After(utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)):
	case <-ctx.Done():
	}
}

// fetchSourceMaps retrieves the source map published beside each artifact, when one is.
func fetchSourceMaps(ctx context.Context, config enumerate.EnumerateJavascriptConfig, artifacts []*artifact) ([]*artifact, []string) {
	maps := []*artifact{}
	errors := []string{}

	for _, current := range artifacts {
		if current.details.Kind == enumerate.JavascriptArtifactKindSourceMap {
			continue
		}
		mapURL := strings.SplitN(current.details.Url, "?", 2)[0] + ".map"
		sourceMap, err := fetchArtifact(ctx, config, mapURL, enumerate.JavascriptArtifactKindSourceMap, &current.details.Url)
		if err != nil {
			continue
		}
		if sourceMap.details.StatusCode == nil || *sourceMap.details.StatusCode != 200 {
			continue
		}
		maps = append(maps, sourceMap)
	}
	return maps, errors
}

// fetchArtifact retrieves one artifact, rejecting bodies an SPA catch-all returned instead of code.
func fetchArtifact(ctx context.Context, config enumerate.EnumerateJavascriptConfig, target string, kind enumerate.JavascriptArtifactKind, discoveredFrom *string) (*artifact, error) {
	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", target, err)
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
		Request:       &httpRequest,
		MaxRedirects:  config.MaxRedirects,
		VerifyTls:     config.VerifyTls,
		Timeout:       config.Timeout,
		UserAgent:     config.UserAgent,
		RequestMethod: common.RequestMethodStandard,
		Cookies:       config.Cookies,
	}
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)

	response, err := request.SendRequest(ctx, sendConfig)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", target, err)
	}
	if response == nil || response.Response == nil {
		return nil, fmt.Errorf("fetching %s: no response", target)
	}

	details := &enumerate.JavascriptArtifact{
		Url:            target,
		Kind:           kind,
		StatusCode:     response.Response.StatusCode,
		DiscoveredFrom: discoveredFrom,
	}
	if contentType := firstHeaderValue(response.Response.ResponseHeaders, "Content-Type"); contentType != "" {
		details.ContentType = &contentType
	}

	bodyPtr := requesthelpers.GetResponseBodyStringFromBodyStruct(response.Response.ResponseBody)
	if bodyPtr == nil {
		return nil, fmt.Errorf("fetching %s: empty body", target)
	}
	body := *bodyPtr
	details.SizeBytes = len(body)

	if details.StatusCode == nil || *details.StatusCode != 200 {
		return nil, fmt.Errorf("fetching %s: unexpected status", target)
	}
	// A single-page app serves its shell for any unknown path, so a 200 alone does not mean the
	// chunk exists.
	if looksLikeHTML(body, details.ContentType) {
		return nil, fmt.Errorf("fetching %s: served HTML rather than JavaScript", target)
	}

	return &artifact{details: details, source: []byte(body)}, nil
}

// resolveChunkURL places a declared chunk name against the publicPath, falling back to the bundle.
func resolveChunkURL(entryURL string, publicPath string, name string) (string, error) {
	base, err := url.Parse(entryURL)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", entryURL, err)
	}
	// A `//`-prefixed name parses as a host, which would redirect the fetch off the target.
	if strings.HasPrefix(name, "//") {
		return "", fmt.Errorf("resolving %s: protocol-relative chunk name", name)
	}

	reference, err := url.Parse(name)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", name, err)
	}
	if publicPath == "" || reference.IsAbs() || strings.HasPrefix(name, "/") {
		return base.ResolveReference(reference).String(), nil
	}

	root, err := url.Parse(publicPath)
	if err != nil {
		return "", fmt.Errorf("resolving public path %s: %w", publicPath, err)
	}
	if !root.IsAbs() {
		root = base.ResolveReference(root)
	}
	return root.JoinPath(name).String(), nil
}

func looksLikeHTML(body string, contentType *string) bool {
	if contentType != nil && strings.Contains(strings.ToLower(*contentType), "text/html") {
		return true
	}
	leading := strings.ToLower(strings.TrimSpace(body))
	if len(leading) > 512 {
		leading = leading[:512]
	}
	return strings.HasPrefix(leading, "<!doctype html") || strings.HasPrefix(leading, "<html")
}

func firstHeaderValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func artifactDetails(artifacts []*artifact) []*enumerate.JavascriptArtifact {
	details := make([]*enumerate.JavascriptArtifact, 0, len(artifacts))
	for _, current := range artifacts {
		details = append(details, current.details)
	}
	return details
}

func dedupeEndpoints(endpoints []*enumerate.JavascriptEndpoint) []*enumerate.JavascriptEndpoint {
	seen := map[string]struct{}{}
	out := make([]*enumerate.JavascriptEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		method := ""
		if endpoint.Method != nil {
			method = string(*endpoint.Method)
		}
		base := ""
		if endpoint.BaseUrl != nil {
			base = *endpoint.BaseUrl
		}
		key := method + " " + base + " " + endpoint.Path
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

func dedupeSecrets(secrets []*enumerate.JavascriptSecret) []*enumerate.JavascriptSecret {
	seen := map[string]struct{}{}
	out := make([]*enumerate.JavascriptSecret, 0, len(secrets))
	for _, secret := range secrets {
		if secret == nil {
			continue
		}
		value := ""
		if secret.Value != nil {
			value = *secret.Value
		}
		key := secret.Kind + " " + value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, secret)
	}
	return out
}

// targetHosts returns the hosts of the analyzed bundles, used to prefer a same-origin API base.
func targetHosts(targets []string) []string {
	seen := map[string]struct{}{}
	hosts := []string{}
	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

func sortedSet(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
