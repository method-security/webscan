package discoverwordlist

import (
	// Standard
	"context"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	goquery "github.com/PuerkitoBio/goquery"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// commentRegex matches HTML comments <!-- ... -->
var commentRegex = regexp.MustCompile(`<!--(.*?)-->`)

// buildWordRegex builds a regex that matches words of at least minLen letters.
func buildWordRegex(minLen int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`\b[A-Za-z]{%d,}\b`, minLen))
}

// createRequestConfig builds a SendHttpRequestConfig for a standard GET request.
// It uses SplitTargetURL to correctly populate BaseUrl, Path, and Params.Query so
// that ConstructURL never dereferences a nil Params pointer and query-string URLs
// are fetched accurately.
func createRequestConfig(rawURL string, config discover.DiscoverWordlistConfig) (common.SendHttpRequestConfig, error) {
	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(rawURL)
	if err != nil {
		return common.SendHttpRequestConfig{}, fmt.Errorf("invalid URL %s: %w", rawURL, err)
	}

	httpReq := &common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query: queryParams,
		},
	}
	// IgnoreCrossDomainRedirects is always false: the HTTP layer uses exact
	// hostname matching for redirects, which would block canonical redirects
	// (e.g. example.com → www.example.com) and drop in-scope pages even when
	// IgnoreCrossDomain is enabled. Cross-domain filtering is handled after
	// redirect resolution, at the link-enqueueing stage via utils.IsHostInScope.
	return common.SendHttpRequestConfig{
		Request:                    httpReq,
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: false,
		RequestMethod:              common.RequestMethodStandard,
		UserAgent:                  config.UserAgent,
	}, nil
}

// extractWords pulls words from page content according to the config options.
func extractWords(htmlContent string, config discover.DiscoverWordlistConfig) []string {
	wordRe := buildWordRegex(config.MinWordLength)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}

	var builder strings.Builder

	// Main body text
	builder.WriteString(doc.Find("body").Text())
	builder.WriteString(" ")

	// Meta tag content values — include all meta[content] variants: name-based
	// (description, keywords), property-based (Open Graph, Twitter Cards), and
	// http-equiv. The prior selector meta[name][content] excluded property tags.
	if config.IncludeMetadata {
		doc.Find("meta[content]").Each(func(_ int, s *goquery.Selection) {
			if content, exists := s.Attr("content"); exists {
				builder.WriteString(content)
				builder.WriteString(" ")
			}
		})
	}

	// HTML comment text
	if config.IncludeComments {
		matches := commentRegex.FindAllStringSubmatch(htmlContent, -1)
		for _, m := range matches {
			if len(m) > 1 {
				builder.WriteString(m[1])
				builder.WriteString(" ")
			}
		}
	}

	// Image alt text
	if config.IncludeAltText {
		doc.Find("img[alt]").Each(func(_ int, s *goquery.Selection) {
			if alt, exists := s.Attr("alt"); exists {
				builder.WriteString(alt)
				builder.WriteString(" ")
			}
		})
	}

	return wordRe.FindAllString(builder.String(), -1)
}

// extractLinks returns absolute URLs found in <a href=""> elements on the page.
func extractLinks(htmlContent, pageURL string, config discover.DiscoverWordlistConfig) []string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var links []string

	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists || href == "" || strings.HasPrefix(href, "#") ||
			strings.HasPrefix(href, "javascript:") ||
			strings.HasPrefix(href, "data:") ||
			strings.HasPrefix(href, "vbscript:") {
			return
		}

		ref, err := url.Parse(href)
		if err != nil {
			return
		}

		resolvedURL := base.ResolveReference(ref)
		// Only follow http/https links — skip mailto:, ftp:, tel:, and other schemes
		// that were not caught by the early-exit guards above.
		if resolvedURL.Scheme != "http" && resolvedURL.Scheme != "https" {
			return
		}

		resolved := resolvedURL.String()
		// Strip fragment
		if idx := strings.Index(resolved, "#"); idx >= 0 {
			resolved = resolved[:idx]
		}
		// Normalize trailing slash so that e.g. "/page" and "/page/" are treated
		// as the same URL and not fetched twice (consistent with route discovery).
		resolved = strings.TrimRight(resolved, "/")

		// Cross-domain check: only enqueue links whose host is the crawl seed's
		// host (config.Target) or a subdomain of it. utils.IsHostInScope anchors on the
		// full target host, so the target host and its children are accepted while
		// the apex and sibling subdomains are excluded. pageURL must NOT be used as
		// a secondary scope anchor here — when a redirect lands on another host,
		// pageURL is that off-scope host, and allowing links in scope with pageURL
		// would cause the entire off-scope site to be crawled despite
		// IgnoreCrossDomain being set.
		if config.IgnoreCrossDomain && !utils.IsHostInScope(config.Target, resolved) {
			return
		}

		if _, visited := seen[resolved]; !visited {
			seen[resolved] = struct{}{}
			links = append(links, resolved)
		}
	})

	return links
}

// PerformWordlistCapture crawls the target URL to the configured spider depth and
// returns a DiscoverWordlistReport containing all unique words found.
func PerformWordlistCapture(ctx context.Context, config discover.DiscoverWordlistConfig) discover.DiscoverWordlistReport {
	log := svc1log.FromContext(ctx)

	// Initialise report
	report := discover.DiscoverWordlistReport{
		Config: &config,
		Result: &discover.DiscoverWordlistResult{
			Target: config.Target,
		},
	}

	// Shared state
	var mu sync.Mutex
	wordCounts := make(map[string]int)
	visitedURLs := make(map[string]struct{})
	allCrawled := []string{}
	var errors []string

	// BFS setup
	urlsToVisit := []string{config.Target}
	currentDepth := 0

	for len(urlsToVisit) > 0 && currentDepth < config.SpiderDepth {
		urlsAtDepth := urlsToVisit
		var nextDepthURLs []string
		var nextDepthMu sync.Mutex

		log.Info("Visiting URLs at depth", svc1log.SafeParam("depth", currentDepth))

		var wg sync.WaitGroup
		errChan := make(chan string, len(urlsAtDepth))

		maxGoroutines := runtime.GOMAXPROCS(0)
		if config.Threads > 0 {
			maxGoroutines = config.Threads
		}
		semaphore := make(chan struct{}, maxGoroutines)

		for _, rawURL := range urlsAtDepth {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(targetURL string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				// Skip already-visited URLs
				mu.Lock()
				if _, visited := visitedURLs[targetURL]; visited {
					mu.Unlock()
					return
				}
				visitedURLs[targetURL] = struct{}{}
				mu.Unlock()

				// unmarkVisited removes targetURL from visitedURLs so that a later
				// depth can retry it if the URL is re-discovered via another link.
				unmarkVisited := func() {
					mu.Lock()
					delete(visitedURLs, targetURL)
					mu.Unlock()
				}

				if delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter); delay > 0 {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						// Unmark on cancel so a later depth can retry this URL.
						unmarkVisited()
						return
					}
				}

				log.Info("Fetching URL for wordlist", svc1log.SafeParam("url", targetURL))

				requestConfig, err := createRequestConfig(targetURL, config)
				if err != nil {
					unmarkVisited()
					errChan <- fmt.Sprintf("error creating request config for %s: %s", targetURL, err)
					return
				}

				resp, err := request.SendRequest(ctx, requestConfig)
				if err != nil {
					unmarkVisited()
					errChan <- fmt.Sprintf("error fetching %s: %s", targetURL, err)
					return
				}

				if resp == nil || resp.Response == nil || resp.Response.ResponseBody == nil {
					unmarkVisited()
					errChan <- fmt.Sprintf("no response body from %s", targetURL)
					return
				}

				bodyPtr := requesthelpers.GetResponseBodyStringFromBodyStruct(resp.Response.ResponseBody)
				if bodyPtr == nil {
					unmarkVisited()
					errChan <- fmt.Sprintf("empty response body from %s", targetURL)
					return
				}
				bodyStr := *bodyPtr

				// Determine the canonical final URL after all redirects (including
				// trailing-slash hops, which send.go now always appends to
				// RedirectChain before returning).
				finalURL := targetURL
				if resp.Response != nil && len(resp.Response.RedirectChain) > 0 {
					finalURL = resp.Response.RedirectChain[len(resp.Response.RedirectChain)-1]
				}

				// Record crawled URL; also mark the final redirect destination as
				// visited so that if another path discovers the canonical URL directly
				// it isn't fetched a second time.
				mu.Lock()
				allCrawled = append(allCrawled, targetURL)
				if finalURL != targetURL {
					visitedURLs[strings.TrimRight(finalURL, "/")] = struct{}{}
				}
				mu.Unlock()

				// isInScope is true when the final page is within the crawl scope:
				// either IgnoreCrossDomain is off (crawl anything) or the final
				// URL is on the same host as config.Target or a subdomain of it.
				// utils.IsHostInScope anchors on the full target host, so the target host
				// and its children are accepted while the apex and sibling
				// subdomains are excluded.
				isInScope := !config.IgnoreCrossDomain || utils.IsHostInScope(config.Target, finalURL)

				if isInScope {
					words := extractWords(bodyStr, config)
					mu.Lock()
					for _, w := range words {
						wordCounts[strings.ToLower(w)]++
					}
					mu.Unlock()
				}

				// Skip link extraction for off-scope pages: when IgnoreCrossDomain
				// is enabled and the response landed on a different registrable
				// domain, we should not enqueue links found on that page even
				// though extractLinks would filter them against config.Target.
				// Trusting link discovery from external pages could introduce
				// unexpected crawl paths.
				if !isInScope {
					return
				}

				// Use the final post-redirect URL as the base for link resolution so
				// that relative hrefs resolve against the correct host, not the
				// original pre-redirect URL.  With trailing-slash redirects now
				// tracked in RedirectChain, this is always the true canonical URL.
				links := extractLinks(bodyStr, finalURL, config)
				for _, link := range links {
					mu.Lock()
					_, alreadyVisited := visitedURLs[link]
					mu.Unlock()
					if !alreadyVisited {
						nextDepthMu.Lock()
						nextDepthURLs = append(nextDepthURLs, link)
						nextDepthMu.Unlock()
					}
				}
			}(rawURL)
		}

		wg.Wait()
		close(errChan)

		for e := range errChan {
			errors = append(errors, e)
		}

		urlsToVisit = nextDepthURLs
		currentDepth++
	}

	// Build sorted word entries
	words := make([]*discover.WordlistEntry, 0, len(wordCounts))
	for word, count := range wordCounts {
		words = append(words, &discover.WordlistEntry{
			Word:  word,
			Count: count,
		})
	}
	sort.Slice(words, func(i, j int) bool {
		return words[i].Word < words[j].Word
	})

	// Sort crawled URLs for deterministic output regardless of goroutine
	// completion order.
	sort.Strings(allCrawled)

	totalUnique := len(words)
	report.Result.Words = words
	report.Result.TotalUnique = &totalUnique
	report.Result.UrlsCrawled = allCrawled
	report.Errors = errors

	return report
}
