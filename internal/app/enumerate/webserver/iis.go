package enumerate

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

func PerformAppEnumerateWebserverIIS(ctx context.Context, cfg *webscan.AppEnumerateIisConfig) webscan.AppEnumerateIisReport {
	// -----------------------------------------------------------------------------
	// Entry point exposed to the wider application
	// -----------------------------------------------------------------------------

	rpt := webscan.AppEnumerateIisReport{Config: cfg}

	// Concurrency controls
	nWorkers := runtime.GOMAXPROCS(0)
	if cfg.Threads != nil {
		nWorkers = *cfg.Threads
	}
	sem := make(chan struct{}, nWorkers)

	var wg sync.WaitGroup
	resChan := make(chan *webscan.AppEnumerateIisTargetInfo, len(cfg.Targets))
	errChan := make(chan []string, len(cfg.Targets))

	for _, tgt := range cfg.Targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			r, e := enumerateTarget(t, cfg.Timeout)
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

func enumerateTarget(target string, timeout int) (webscan.AppEnumerateIisTargetInfo, []string) {
	// -----------------------------------------------------------------------------
	// Per‑target routine – minimal probing
	// -----------------------------------------------------------------------------

	out := webscan.AppEnumerateIisTargetInfo{Target: target}
	var errs []string
	var reqs []*common.RequestInfo

	site, rqs, es := enumerateSite(target, timeout)
	reqs = append(reqs, rqs...)
	errs = append(errs, es...)

	if site != nil {
		out.Sites = []*webscan.IisSite{site}
	}
	out.Requests = reqs
	return out, errs
}

func enumerateSite(target string, timeout int) (*webscan.IisSite, []*common.RequestInfo, []string) {
	// -----------------------------------------------------------------------------
	// Core logic: grab headers, parse versions, optional 404 scrape, 401 auth list
	// -----------------------------------------------------------------------------

	var errs []string
	var reqs []*common.RequestInfo

	// --------- Parse & normalise URL ---------
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, []string{fmt.Sprintf("invalid URL %s: %v", target, err)}
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	path := u.Path
	if path == "" {
		path = "/"
	}

	// --------- Baseline GET ---------
	root := utils.PerformRequestScan(baseURL, path, common.HttpMethodGet, common.RequestParams{}, timeout, true)
	reqs = append(reqs, &root)

	if root.StatusCode == nil {
		return nil, reqs, []string{fmt.Sprintf("no response from %s", target)}
	}

	site := &webscan.IisSite{}
	parseBanners(site, &root) // Server & ASP.NET versions

	// --------- If server version still unknown, scrape 404 page ---------
	if site.Server == nil || site.Server.Version == nil {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		nf := utils.PerformRequestScan(baseURL, fmt.Sprintf("/nonexistent_%d.aspx", r.Intn(9e6)), common.HttpMethodGet, common.RequestParams{}, timeout, true)
		reqs = append(reqs, &nf)
		if nf.ResponseBody != nil {
			if v := parseIisVersionFromBody(*nf.ResponseBody); v != "" {
				site.Server = &webscan.WebServerInfo{Name: "Microsoft-IIS", Version: &v}
			}
		}
	}

	// --------- Capture auth schemes when 401 ---------
	if root.StatusCode != nil && *root.StatusCode == 401 {
		auths := getHeaderValues(&root, "WWW-Authenticate")
		if len(auths) > 0 {
			site.AuthenticationMethods = auths
		}
	}

	return site, reqs, errs
}

var iisRe = regexp.MustCompile(`(?i)(Microsoft-IIS)/(\d+\.\d+)`)

func parseBanners(s *webscan.IisSite, r *common.RequestInfo) {
	// -----------------------------------------------------------------------------
	// Helper: banner & header parsing
	// -----------------------------------------------------------------------------

	serverHdr := getHeader(r, "Server")
	if serverHdr != "" {
		if matches := iisRe.FindStringSubmatch(serverHdr); len(matches) > 2 {
			v := matches[2]
			s.Server = &webscan.WebServerInfo{Name: "Microsoft-IIS", Version: &v}
		} else {
			s.Server = &webscan.WebServerInfo{Name: serverHdr}
		}
	}

	// Get framework version from X-AspNet-Version
	aspVer := getHeader(r, "X-AspNet-Version")
	var version *string
	if aspVer != "" {
		version = &aspVer
	}

	// Get framework name from X-Powered-By
	if xp := getHeader(r, "X-Powered-By"); xp != "" {
		s.Frameworks = append(s.Frameworks, &webscan.WebFrameworkInfo{Name: xp, Version: version})
	}
}

var bodyVerRe = regexp.MustCompile(`(?i)IIS\s*(\d+\.\d+)`)

func parseIisVersionFromBody(b string) string {
	// -----------------------------------------------------------------------------
	// Helper: scrape version string from default IIS error pages
	// -----------------------------------------------------------------------------

	if m := bodyVerRe.FindStringSubmatch(b); len(m) > 1 {
		return m[1]
	}
	return ""
}

func getHeader(r *common.RequestInfo, name string) string {
	// -----------------------------------------------------------------------------
	// Generic header helpers (case‑insensitive)
	// -----------------------------------------------------------------------------

	if r.ResponseHeaders == nil {
		return ""
	}
	if v, ok := r.ResponseHeaders[name]; ok {
		return v
	}
	for hn, hv := range r.ResponseHeaders {
		if strings.EqualFold(hn, name) {
			return hv
		}
	}
	return ""
}

func getHeaderValues(r *common.RequestInfo, name string) []string {
	raw := getHeader(r, name)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
