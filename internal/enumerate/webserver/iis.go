package enumerate

import (
	// Standard
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"runtime"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratewebserverfern "github.com/Method-Security/webscan/generated/go/enumerate/webserver"

	// Utils
	"github.com/Method-Security/webscan/internal/enumerate/general"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createSendHTTPRequestConfig(baseURL, path string, config *enumeratewebserverfern.EnumerateWebserverIisConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformAppEnumerateWebserverIIS performs enumeration of IIS webservers for the given config and returns a report.
func PerformAppEnumerateWebserverIIS(ctx context.Context, config enumeratewebserverfern.EnumerateWebserverIisConfig) enumeratewebserverfern.EnumerateWebserverIisReport {
	rpt := enumeratewebserverfern.EnumerateWebserverIisReport{Config: &config}

	// Concurrency controls
	nWorkers := runtime.GOMAXPROCS(0)
	if config.Threads > 0 {
		nWorkers = config.Threads
	}
	sem := make(chan struct{}, nWorkers)

	var wg sync.WaitGroup
	resChan := make(chan *enumeratewebserverfern.EnumerateWebserverIisTarget, len(config.Targets))
	errChan := make(chan []string, len(config.Targets))

	for _, tgt := range config.Targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			r, e := enumerateTarget(ctx, t, &config)
			resChan <- &r
			if len(e) > 0 {
				errChan <- e
			}
		}(tgt)
	}

	wg.Wait()
	close(resChan)
	close(errChan)

	for r := range resChan {
		rpt.Targets = append(rpt.Targets, r)
	}
	for e := range errChan {
		rpt.Errors = append(rpt.Errors, e...)
	}
	return rpt
}

// enumerateTarget is the per‑target routine – minimal probing
func enumerateTarget(ctx context.Context, target string, config *enumeratewebserverfern.EnumerateWebserverIisConfig) (enumeratewebserverfern.EnumerateWebserverIisTarget, []string) {
	out := enumeratewebserverfern.EnumerateWebserverIisTarget{Target: target}
	var errs []string
	var reqs []*common.HttpRequestResponse

	site, rqs, es := enumerateSite(ctx, target, config)
	reqs = append(reqs, rqs...)
	errs = append(errs, es...)

	if site != nil {
		out.Site = site
	}
	out.Requests = reqs
	return out, errs
}

// enumerateSite is the core logic: grab headers, parse versions, optional 404 scrape, 401 auth list
func enumerateSite(ctx context.Context, target string, config *enumeratewebserverfern.EnumerateWebserverIisConfig) (*enumeratewebserverfern.IisSiteDetails, []*common.HttpRequestResponse, []string) {
	var errs []string
	var reqs []*common.HttpRequestResponse

	// Parse & normalise URL
	baseURL, path, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return nil, nil, []string{fmt.Sprintf("invalid URL %s: %v", target, err)}
	}

	requestConfig := createSendHTTPRequestConfig(baseURL, path, config)

	// Baseline GET
	root, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error capturing content for %s: %v", target, err))
		if root != nil && general.RateLimitDetected(root, false) {
			errs = append(errs, "rate limit detected")
		}
		return nil, reqs, errs
	}
	reqs = append(reqs, root)

	site := &enumeratewebserverfern.IisSiteDetails{}
	parseBanners(site, root) // Server & ASP.NET versions

	// If server version still unknown, scrape 404 page
	if site.Server == nil || site.Server.Version == nil {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		requestConfig := createSendHTTPRequestConfig(baseURL, fmt.Sprintf("%s/nonexistent_%d.aspx", path, r.Intn(9e6)), config)

		nf, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error capturing 404 page for %s: %v", target, err))
			if nf != nil && general.RateLimitDetected(nf, root.Response != nil && root.Response.StatusCode != nil && *root.Response.StatusCode == 200) {
				errs = append(errs, "rate limit detected")
			}
		}
		if nf != nil && nf.Response != nil && nf.Response.ResponseBody != nil {
			if v := parseIisVersionFromBody(*requesthelpers.GetResponseBodyStringFromBodyStruct(nf.Response.ResponseBody)); v != "" {
				site.Server = &enumeratewebserverfern.IisWebServerDetails{Name: "Microsoft-IIS", Version: &v}
			}
		}
	}

	// Capture auth schemes when 401
	if root.Response != nil && root.Response.StatusCode != nil && *root.Response.StatusCode == 401 {
		auth := requesthelpers.GetHeaderValueFromHeaderMap(root.Response.ResponseHeaders, "WWW-Authenticate")
		if auth != nil {
			site.AuthenticationMethods = append(site.AuthenticationMethods, *auth)
		}
	}

	return site, reqs, errs
}

var iisRe = regexp.MustCompile(`(?i)(Microsoft-IIS)/(\d+\.\d+)`)

// parseBanners is a helper: banner & header parsing
func parseBanners(s *enumeratewebserverfern.IisSiteDetails, r *common.HttpRequestResponse) {
	if r == nil || r.Response == nil || r.Response.ResponseHeaders == nil {
		return
	}

	serverHdr := requesthelpers.GetHeaderValueFromHeaderMap(r.Response.ResponseHeaders, "Server")
	if serverHdr != nil {
		if matches := iisRe.FindStringSubmatch(*serverHdr); len(matches) > 2 {
			v := matches[2]
			s.Server = &enumeratewebserverfern.IisWebServerDetails{Name: "Microsoft-IIS", Version: &v}
		} else {
			s.Server = &enumeratewebserverfern.IisWebServerDetails{Name: *serverHdr}
		}
	}

	// Get framework version from X-AspNet-Version
	aspVer := requesthelpers.GetHeaderValueFromHeaderMap(r.Response.ResponseHeaders, "X-AspNet-Version")
	var version *string
	if aspVer != nil {
		version = aspVer
	}

	// Get framework name from X-Powered-By
	if xp := requesthelpers.GetHeaderValueFromHeaderMap(r.Response.ResponseHeaders, "X-Powered-By"); xp != nil {
		s.Frameworks = append(s.Frameworks, &enumeratewebserverfern.IisWebFrameworkDetails{Name: *xp, Version: version})
	}
}

var bodyVerRe = regexp.MustCompile(`(?i)IIS\s*(\d+\.\d+)`)

// parseIisVersionFromBody is a helper: scrape version string from default IIS error pages
func parseIisVersionFromBody(b string) string {
	if m := bodyVerRe.FindStringSubmatch(b); len(m) > 1 {
		return m[1]
	}
	return ""
}
