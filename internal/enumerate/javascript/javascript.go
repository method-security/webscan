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

	report.Result.WebApplications = analysis.applications
	report.Result.UnrootedEndpoints = analysis.unrooted
	report.Errors = append(report.Errors, collector.errors...)
	return report
}

// collector accumulates artifacts across the stages, keeping one record per URL.
type collector struct {
	config    enumerate.EnumerateJavascriptConfig
	artifacts []*artifact
	// claimed guards every URL the run has decided to retrieve, so no URL is fetched twice however
	// many pages or manifests name it.
	claimed map[string]struct{}
	byURL   map[string]*artifact
	// owners records the application each URL was reached for. A bundle a CDN serves to two
	// applications belongs to both, so this is a list rather than a single value.
	owners    map[string][]string
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

// applicationBaseURL reduces a URL to the origin serving it.
func applicationBaseURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func newCollector(config enumerate.EnumerateJavascriptConfig) *collector {
	return &collector{
		config:    config,
		claimed:   map[string]struct{}{},
		byURL:     map[string]*artifact{},
		owners:    map[string][]string{},
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
		owners := []string{applicationBaseURL(seed)}
		c.addOwners(seed, owners)

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
			c.enqueue(reference, enumerate.JavascriptArtifactKindEntry, seed, owners)
		}
	}
}

// enqueue schedules a URL for retrieval if no stage has claimed it yet, recording the applications
// it was reached for either way — a URL another application already claimed still belongs to this one.
func (c *collector) enqueue(target string, kind enumerate.JavascriptArtifactKind, discoveredFrom string, owners []string) {
	c.addOwners(target, owners)
	if !c.claim(target) {
		return
	}
	source := discoveredFrom
	c.queue = append(c.queue, queued{url: target, kind: kind, discoveredFrom: &source})
}

// addOwners records the applications a URL belongs to, keeping the order they were reached in.
func (c *collector) addOwners(target string, owners []string) {
	for _, owner := range owners {
		if owner == "" {
			continue
		}
		known := false
		for _, existing := range c.owners[target] {
			if existing == owner {
				known = true
				break
			}
		}
		if !known {
			c.owners[target] = append(c.owners[target], owner)
		}
	}
}

// ownersOf returns the applications an artifact belongs to, falling back to the origin serving it.
func (c *collector) ownersOf(target string) []string {
	if owners := c.owners[target]; len(owners) > 0 {
		return owners
	}
	if base := applicationBaseURL(target); base != "" {
		return []string{base}
	}
	return nil
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
				c.enqueue(chunkURL, enumerate.JavascriptArtifactKindChunk, current.details.Url, c.ownersOf(current.details.Url))
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
		c.enqueue(mapURL, enumerate.JavascriptArtifactKindSourceMap, current.details.Url, c.ownersOf(current.details.Url))
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

// analysisResult is what the analysis stage produced, grouped by the application it belongs to.
type analysisResult struct {
	applications []*enumerate.JavascriptApplicationDetails
	unrooted     []*enumerate.JavascriptEndpoint
}

// applicationBucket accumulates one application's artifacts and findings during analysis.
type applicationBucket struct {
	baseURL   string
	pages     []*enumerate.JavascriptArtifact
	local     []*enumerate.JavascriptArtifact
	remote    []*enumerate.JavascriptArtifact
	origins   map[string]struct{}
	bases     []string
	endpoints []*javascripthelpers.Endpoint
	secrets   []*enumerate.JavascriptSecret
}

// analyze runs the extractor once per retrieved artifact and groups what it found under the
// application the artifact was retrieved for, rooting each application against its own bases.
func (c *collector) analyze(config enumerate.EnumerateJavascriptConfig) analysisResult {
	buckets := map[string]*applicationBucket{}
	order := []string{}

	for _, current := range c.artifacts {
		owners := c.ownersOf(current.details.Url)
		if len(owners) == 0 {
			continue
		}

		var found javascripthelpers.Analysis
		if current.source != nil {
			found = javascripthelpers.AnalyzeSource(current.source, current.details.Url, config.AnalysisWindowBytes, config.AnalysisWindowOverlapBytes)
		}

		for _, owner := range owners {
			bucket, exists := buckets[owner]
			if !exists {
				bucket = &applicationBucket{baseURL: owner, origins: map[string]struct{}{}}
				buckets[owner] = bucket
				order = append(order, owner)
			}

			if current.details.Kind == enumerate.JavascriptArtifactKindPage {
				bucket.pages = append(bucket.pages, current.details)
				continue
			}
			if utils.IsHostInScope(owner, current.details.Url) {
				bucket.local = append(bucket.local, current.details)
			} else {
				bucket.remote = append(bucket.remote, current.details)
			}

			// Cloned because rooting rewrites the endpoint, and an artifact two applications share
			// roots against a different base for each of them.
			for _, endpoint := range found.Endpoints {
				bucket.endpoints = append(bucket.endpoints, endpoint.Clone())
			}
			bucket.secrets = append(bucket.secrets, found.Secrets...)
			for _, origin := range found.Origins {
				bucket.origins[origin] = struct{}{}
			}
		}
	}

	// An endpoint belongs to the host that serves it, which is not always the application whose
	// bundle named it — a bundle routinely calls an API on a sibling host.
	served := map[string][]*javascripthelpers.Endpoint{}
	unrooted := []*javascripthelpers.Endpoint{}
	sort.Strings(order)
	for _, owner := range order {
		bucket := buckets[owner]
		hosts := targetHosts([]string{owner})
		bucket.bases = javascripthelpers.BaseCandidatesInScope(sortedSet(bucket.origins), hosts, config.IgnoreCrossDomainEndpoints)

		for _, endpoint := range javascripthelpers.RootEndpoints(dedupeEndpoints(bucket.endpoints), bucket.bases, hosts) {
			if !endpoint.Rooted {
				unrooted = append(unrooted, endpoint)
				continue
			}
			// A root-relative path resolves against the application that loaded the bundle.
			if endpoint.BaseURL == "" {
				endpoint.BaseURL = owner
			}
			// An absolute URL to an unrelated host is a link the bundle happens to contain, not an
			// endpoint of anything being scanned. Left in it would stand up an application per
			// social network the page links to.
			if config.IgnoreCrossDomainEndpoints && !c.inScope(endpoint.BaseURL) {
				continue
			}
			served[endpoint.BaseURL] = append(served[endpoint.BaseURL], endpoint)
			if _, exists := buckets[endpoint.BaseURL]; !exists {
				buckets[endpoint.BaseURL] = &applicationBucket{baseURL: endpoint.BaseURL, origins: map[string]struct{}{}}
				order = append(order, endpoint.BaseURL)
			}
		}
	}

	sort.Strings(order)
	applications := make([]*enumerate.JavascriptApplicationDetails, 0, len(order))
	for _, base := range order {
		bucket := buckets[base]
		application := &enumerate.JavascriptApplicationDetails{
			BaseUrl:           bucket.baseURL,
			Pages:             bucket.pages,
			BaseUrlCandidates: bucket.bases,
			Endpoints:         detailsOf(dedupeEndpoints(served[base])),
			Secrets:           dedupeSecrets(bucket.secrets),
		}
		if len(bucket.local) > 0 || len(bucket.remote) > 0 {
			application.Bundles = &enumerate.JavascriptBundleDetails{Local: bucket.local, Remote: bucket.remote}
		}
		applications = append(applications, application)
	}

	return analysisResult{applications: applications, unrooted: detailsOf(dedupeEndpoints(unrooted))}
}

// inScope reports a URL served by a target's host or a subdomain of it.
func (c *collector) inScope(target string) bool {
	for _, configured := range c.config.Targets {
		if base := applicationBaseURL(configured); base != "" && utils.IsHostInScope(base, target) {
			return true
		}
	}
	return false
}

// detailsOf unwraps the reported endpoint from each analysis record.
func detailsOf(endpoints []*javascripthelpers.Endpoint) []*enumerate.JavascriptEndpoint {
	out := make([]*enumerate.JavascriptEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		out = append(out, endpoint.Details)
	}
	return out
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

func dedupeEndpoints(endpoints []*javascripthelpers.Endpoint) []*javascripthelpers.Endpoint {
	seen := map[string]struct{}{}
	out := make([]*javascripthelpers.Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == nil || endpoint.Details == nil {
			continue
		}
		method := ""
		if endpoint.Details.Method != nil {
			method = string(*endpoint.Details.Method)
		}
		key := method + " " + endpoint.BaseURL + " " + endpoint.Details.Path
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
		name := ""
		if secret.Name != nil {
			name = *secret.Name
		}
		value := ""
		if secret.Value != nil {
			value = *secret.Value
		}
		key := secret.Kind + " " + name + " " + value
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
