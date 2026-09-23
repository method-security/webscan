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

// artifact is one fetched body plus the record kept about it.
type artifact struct {
	details  *enumerate.JavascriptArtifact
	source   []byte
	expanded bool
}

// PerformJavascriptEnumeration analyzes the JavaScript an application serves, returning an
// EnumerateJavascriptReport.
//
// Work is staged so nothing is fetched twice. Every target is resolved to the bundles it references
// first, that set is deduplicated, only then are the bundles retrieved and their manifests expanded,
// and analysis runs once per unique artifact. Pages routinely share entry bundles, so resolving and
// analyzing per target would refetch the same multi-megabyte bundle once per page.
func PerformJavascriptEnumeration(ctx context.Context, config enumerate.EnumerateJavascriptConfig) enumerate.EnumerateJavascriptReport {
	log := svc1log.FromContext(ctx)

	report := enumerate.EnumerateJavascriptReport{
		Config: &config,
		Result: &enumerate.EnumerateJavascriptResult{
			Targets: config.Targets,
		},
	}

	collector := newCollector(config)

	log.Info("Resolving targets to the bundles they reference", svc1log.SafeParam("targets", len(config.Targets)))
	collector.resolveSeeds(ctx)

	log.Info("Retrieving referenced bundles", svc1log.SafeParam("bundles", len(collector.pendingBundles())))
	collector.retrieveBundles(ctx)

	if config.FollowChunks {
		log.Info("Expanding declared chunks")
		collector.expandChunks(ctx)
	}
	if config.FetchSourceMaps {
		collector.retrieveSourceMaps(ctx)
	}

	analysis := collector.analyze(config)

	report.Result.Artifacts = collector.artifactDetails()
	report.Result.BaseUrlCandidates = analysis.bases
	report.Result.Endpoints = analysis.endpoints
	report.Result.Secrets = analysis.secrets
	report.Errors = append(report.Errors, collector.errors...)
	return report
}

// collector accumulates artifacts across the stages, keeping one record per URL.
type collector struct {
	config    enumerate.EnumerateJavascriptConfig
	artifacts []*artifact
	// claimed guards every URL the run has decided to retrieve, so no URL is fetched twice however
	// many pages or manifests name it.
	claimed   map[string]struct{}
	byURL     map[string]*artifact
	queue     []queued
	errors    []string
	remaining int
}

// queued is a URL waiting to be retrieved, with where it was found.
type queued struct {
	url            string
	kind           enumerate.JavascriptArtifactKind
	discoveredFrom *string
}

func newCollector(config enumerate.EnumerateJavascriptConfig) *collector {
	return &collector{
		config:    config,
		claimed:   map[string]struct{}{},
		byURL:     map[string]*artifact{},
		remaining: config.MaxArtifacts,
	}
}

// spend takes one retrieval from the budget, reporting whether the budget allowed it.
func (c *collector) spend() bool {
	if c.config.MaxArtifacts <= 0 {
		return true
	}
	if c.remaining <= 0 {
		return false
	}
	c.remaining--
	return true
}

// claim reserves a URL for retrieval, reporting whether this call is the one that took it.
func (c *collector) claim(url string) bool {
	if _, exists := c.claimed[url]; exists {
		return false
	}
	c.claimed[url] = struct{}{}
	return true
}

func (c *collector) pendingBundles() []queued {
	return c.queue
}

// resolveSeeds retrieves every target and reduces it to the bundles it references. A target that is
// itself JavaScript is kept as retrieved; a page contributes the scripts it declares.
func (c *collector) resolveSeeds(ctx context.Context) {
	seeds := javascripthelpers.SortedUnique(c.config.Targets)
	for index, seed := range seeds {
		// Claimed before charged: a target another stage already took costs nothing, and a target
		// the budget refuses is released rather than recorded as handled. Targets are resolved
		// before anything discovered, so an explicit one outranks a reference when the budget is
		// tight.
		if !c.claim(seed) {
			continue
		}
		if !c.spend() {
			delete(c.claimed, seed)
			c.errors = append(c.errors, fmt.Sprintf("skipped %d targets: max-artifacts reached", len(seeds)-index))
			return
		}
		fetched, err := fetchResource(ctx, c.config, seed, enumerate.JavascriptArtifactKindEntry, nil)
		if err != nil {
			c.errors = append(c.errors, err.Error())
			continue
		}

		contentType := ""
		if fetched.details.ContentType != nil {
			contentType = *fetched.details.ContentType
		}
		if !javascripthelpers.LooksLikeHTML(string(fetched.source), contentType) {
			c.record(fetched)
			continue
		}

		// The page is provenance, not something to analyze as JavaScript.
		fetched.details.Kind = enumerate.JavascriptArtifactKindPage
		references := javascripthelpers.ExtractScriptReferences(string(fetched.source), seed)
		count := len(references)
		fetched.details.ReferenceCount = &count
		fetched.source = nil
		c.record(fetched)

		if count == 0 {
			c.errors = append(c.errors, fmt.Sprintf("%s: page references no JavaScript", seed))
			continue
		}
		for _, reference := range references {
			c.enqueue(reference, enumerate.JavascriptArtifactKindEntry, seed)
		}
	}
}

// enqueue schedules a URL for retrieval if no stage has claimed it yet.
func (c *collector) enqueue(url string, kind enumerate.JavascriptArtifactKind, discoveredFrom string) {
	if !c.claim(url) {
		return
	}
	source := discoveredFrom
	c.queue = append(c.queue, queued{url: url, kind: kind, discoveredFrom: &source})
}

// retrieveBundles fetches everything the seed stage queued, honoring the artifact budget.
func (c *collector) retrieveBundles(ctx context.Context) {
	c.drainQueue(ctx, reportFailures)
}

// expandChunks reads the chunk manifest of every retrieved artifact and retrieves what it declares.
// It repeats while new manifests appear, since a chunk may itself carry one.
func (c *collector) expandChunks(ctx context.Context) {
	for pass := 0; pass < maxChunkPasses; pass++ {
		for _, current := range c.artifacts {
			if current.source == nil || current.expanded {
				continue
			}
			current.expanded = true

			source := string(current.source)
			names := javascripthelpers.ExtractWebpackChunkNames(source)
			if len(names) == 0 {
				names = javascripthelpers.ExtractViteChunkNames(source)
			}
			if len(names) == 0 {
				continue
			}

			publicPath := javascripthelpers.ExtractPublicPath(source)
			for _, name := range names {
				chunkURL, err := resolveChunkURL(current.details.Url, publicPath, name)
				if err != nil {
					c.errors = append(c.errors, err.Error())
					continue
				}
				c.enqueue(chunkURL, enumerate.JavascriptArtifactKindChunk, current.details.Url)
			}
		}
		if len(c.queue) == 0 {
			return
		}
		c.drainQueue(ctx, reportFailures)
	}
}

// maxChunkPasses bounds manifest-within-manifest expansion.
const maxChunkPasses = 3

// retrieveSourceMaps fetches the source map published beside each retrieved artifact, when one is.
func (c *collector) retrieveSourceMaps(ctx context.Context) {
	for _, current := range c.artifacts {
		if current.source == nil || current.details.Kind == enumerate.JavascriptArtifactKindSourceMap {
			continue
		}
		mapURL := strings.SplitN(current.details.Url, "?", 2)[0] + ".map"
		c.enqueue(mapURL, enumerate.JavascriptArtifactKindSourceMap, current.details.Url)
	}
	// A missing source map is the normal case, so a failed retrieval is not reported. Budget
	// messages still are, or `--fetch-source-maps` could retrieve nothing and still exit clean.
	c.drainQueue(ctx, quietFailures)
}

// retrievalMode says whether a failed retrieval is worth reporting.
type retrievalMode bool

const (
	reportFailures retrievalMode = false
	quietFailures  retrievalMode = true
)

// drainQueue retrieves everything queued, concurrently and within the artifact budget.
func (c *collector) drainQueue(ctx context.Context, mode retrievalMode) {
	pending := c.queue
	c.queue = nil
	if len(pending) == 0 {
		return
	}

	if c.config.MaxArtifacts > 0 {
		if c.remaining <= 0 {
			c.errors = append(c.errors, fmt.Sprintf("skipped %d artifacts: max-artifacts reached", len(pending)))
			for _, dropped := range pending {
				delete(c.claimed, dropped.url)
			}
			return
		}
		if len(pending) > c.remaining {
			c.errors = append(c.errors, fmt.Sprintf("retrieving %d of %d artifacts: max-artifacts reached", c.remaining, len(pending)))
			// Released so `claimed` only ever holds URLs the run actually retrieves.
			for _, dropped := range pending[c.remaining:] {
				delete(c.claimed, dropped.url)
			}
			pending = pending[:c.remaining]
		}
		c.remaining -= len(pending)
	}

	results := make([]*artifact, len(pending))
	failures := make([]string, len(pending))

	maxConcurrent := runtime.GOMAXPROCS(0)
	if c.config.Threads > 0 {
		maxConcurrent = c.config.Threads
	}
	semaphore := make(chan struct{}, maxConcurrent)

	var waitGroup sync.WaitGroup
	for index, item := range pending {
		waitGroup.Add(1)
		semaphore <- struct{}{}

		go func(index int, item queued) {
			defer waitGroup.Done()
			defer func() { <-semaphore }()

			applyStealthDelay(ctx, c.config)

			retrieved, err := fetchResource(ctx, c.config, item.url, item.kind, item.discoveredFrom)
			if err != nil {
				failures[index] = err.Error()
				return
			}
			contentType := ""
			if retrieved.details.ContentType != nil {
				contentType = *retrieved.details.ContentType
			}
			// A single-page app serves its shell for any unknown path, so a 200 alone does not mean
			// the bundle exists.
			if javascripthelpers.LooksLikeHTML(string(retrieved.source), contentType) {
				failures[index] = fmt.Sprintf("fetching %s: served HTML rather than JavaScript", item.url)
				return
			}
			results[index] = retrieved
		}(index, item)
	}
	waitGroup.Wait()

	for index := range pending {
		if results[index] != nil {
			c.record(results[index])
		}
		if failures[index] != "" && mode == reportFailures {
			c.errors = append(c.errors, failures[index])
		}
	}
}

// record keeps one artifact per URL.
func (c *collector) record(current *artifact) {
	if _, exists := c.byURL[current.details.Url]; exists {
		return
	}
	c.byURL[current.details.Url] = current
	c.artifacts = append(c.artifacts, current)
}

// analysisResult is what the analysis stage produced across every artifact.
type analysisResult struct {
	endpoints []*enumerate.JavascriptEndpoint
	secrets   []*enumerate.JavascriptSecret
	bases     []string
}

// analyze runs the extractor once per retrieved artifact and roots the result against the bases
// pooled from all of them.
func (c *collector) analyze(config enumerate.EnumerateJavascriptConfig) analysisResult {
	endpoints := []*enumerate.JavascriptEndpoint{}
	secrets := []*enumerate.JavascriptSecret{}
	origins := map[string]struct{}{}

	for _, current := range c.artifacts {
		if current.source == nil {
			continue
		}
		found := javascripthelpers.AnalyzeSource(current.source, current.details.Url, config.AnalysisWindowBytes, config.AnalysisWindowOverlapBytes)
		current.details.Analyzed = true
		endpoints = append(endpoints, found.Endpoints...)
		secrets = append(secrets, found.Secrets...)
		for _, origin := range found.Origins {
			origins[origin] = struct{}{}
		}
	}

	hosts := targetHosts(c.config.Targets)
	bases := javascripthelpers.BaseCandidatesInScope(sortedSet(origins), hosts, config.IgnoreCrossDomainEndpoints)
	return analysisResult{
		endpoints: javascripthelpers.RootEndpoints(dedupeEndpoints(endpoints), bases, hosts),
		secrets:   dedupeSecrets(secrets),
		bases:     bases,
	}
}

func (c *collector) artifactDetails() []*enumerate.JavascriptArtifact {
	details := make([]*enumerate.JavascriptArtifact, 0, len(c.artifacts))
	for _, current := range c.artifacts {
		details = append(details, current.details)
	}
	return details
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

func fetchResource(ctx context.Context, config enumerate.EnumerateJavascriptConfig, target string, kind enumerate.JavascriptArtifactKind, discoveredFrom *string) (*artifact, error) {
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

func firstHeaderValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
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
