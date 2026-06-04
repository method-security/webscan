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

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"

	// Utils
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

// isSameDomain returns true when targetURL shares the same effective domain as baseURL.
func isSameDomain(baseURL, targetURL string) bool {
	base, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(base.Hostname(), target.Hostname())
}

// createRequestConfig builds a SendHttpRequestConfig for a standard GET request.
func createRequestConfig(rawURL string, config discover.DiscoverWordlistConfig) (common.SendHttpRequestConfig, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return common.SendHttpRequestConfig{}, fmt.Errorf("invalid URL %s: %w", rawURL, err)
	}

	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	httpReq := &common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
	}
	return common.SendHttpRequestConfig{
		Request:                    httpReq,
		MaxRedirects:               10,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomain,
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

	// Meta tag content values
	if config.IncludeMetadata {
		doc.Find("meta[name][content]").Each(func(_ int, s *goquery.Selection) {
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
		if !exists || href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			return
		}

		ref, err := url.Parse(href)
		if err != nil {
			return
		}

		resolved := base.ResolveReference(ref).String()
		// Strip fragment
		if idx := strings.Index(resolved, "#"); idx >= 0 {
			resolved = resolved[:idx]
		}

		if config.IgnoreCrossDomain && !isSameDomain(pageURL, resolved) {
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

				log.Info("Fetching URL for wordlist", svc1log.SafeParam("url", targetURL))

				requestConfig, err := createRequestConfig(targetURL, config)
				if err != nil {
					errChan <- fmt.Sprintf("error creating request config for %s: %s", targetURL, err)
					return
				}

				resp, err := request.SendRequest(ctx, requestConfig)
				if err != nil {
					errChan <- fmt.Sprintf("error fetching %s: %s", targetURL, err)
					return
				}

				if resp == nil || resp.Response == nil || resp.Response.ResponseBody == nil {
					errChan <- fmt.Sprintf("no response body from %s", targetURL)
					return
				}

				bodyPtr := requesthelpers.GetResponseBodyStringFromBodyStruct(resp.Response.ResponseBody)
				if bodyPtr == nil {
					errChan <- fmt.Sprintf("empty response body from %s", targetURL)
					return
				}
				bodyStr := *bodyPtr

				// Record crawled URL
				mu.Lock()
				allCrawled = append(allCrawled, targetURL)
				mu.Unlock()

				// Extract words and add to counts
				words := extractWords(bodyStr, config)
				mu.Lock()
				for _, w := range words {
					wordCounts[strings.ToLower(w)]++
				}
				mu.Unlock()

				// Extract links for next depth
				links := extractLinks(bodyStr, targetURL, config)
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

	totalUnique := len(words)
	report.Result.Words = words
	report.Result.TotalUnique = &totalUnique
	report.Result.UrlsCrawled = allCrawled
	report.Errors = errors

	return report
}
