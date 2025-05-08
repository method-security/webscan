package enumerate

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"runtime"
	"sync"
	"time"

	enumerateWebserverFern "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	common "github.com/Method-Security/webscan/generated/go/common"
	utils "github.com/Method-Security/webscan/utils"
)

// PerformAppEnumerateWebserverIIS is the entry point exposed to the wider application
func PerformAppEnumerateWebserverIIS(ctx context.Context, cfg *enumerateWebserverFern.AppEnumerateIisConfig) enumerateWebserverFern.AppEnumerateIisReport {
	rpt := enumerateWebserverFern.AppEnumerateIisReport{Config: cfg}

	// Concurrency controls
	nWorkers := runtime.GOMAXPROCS(0)
	if cfg.Threads != nil {
		nWorkers = *cfg.Threads
	}
	sem := make(chan struct{}, nWorkers)

	var wg sync.WaitGroup
	resChan := make(chan *enumerateWebserverFern.AppEnumerateIisTargetInfo, len(cfg.Targets))
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

// enumerateTarget is the per‑target routine – minimal probing
func enumerateTarget(target string, timeout int) (enumerateWebserverFern.AppEnumerateIisTargetInfo, []string) {
	out := enumerateWebserverFern.AppEnumerateIisTargetInfo{Target: target}
	var errs []string
	var reqs []*common.RequestInfo

	site, rqs, es := enumerateSite(target, timeout)
	reqs = append(reqs, rqs...)
	errs = append(errs, es...)

	if site != nil {
		out.Site = site
	}
	out.Requests = reqs
	return out, errs
}

// enumerateSite is the core logic: grab headers, parse versions, optional 404 scrape, 401 auth list
func enumerateSite(target string, timeout int) (*enumerateWebserverFern.IisSite, []*common.RequestInfo, []string) {
	var errs []string
	var reqs []*common.RequestInfo

	// Parse & normalise URL
	baseURL, path, err := utils.SplitTarget(target)
	if err != nil {
		return nil, nil, []string{fmt.Sprintf("invalid URL %s: %v", target, err)}
	}

	// Baseline GET
	root := utils.PerformRequestScan(utils.RequestOptions{
		BaseURL:         baseURL,
		Path:            path,
		Method:          common.HttpMethodGet,
		Params:          common.RequestParams{},
		Timeout:         timeout,
		FollowRedirects: false,
		Insecure:        true,
	})
	if root.StatusCode == nil {
		return nil, reqs, []string{fmt.Sprintf("no response from %s", target)}
	}

	site := &enumerateWebserverFern.IisSite{}
	parseBanners(site, &root) // Server & ASP.NET versions

	// If server version still unknown, scrape 404 page
	if site.Server == nil || site.Server.Version == nil {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		nf := utils.PerformRequestScan(utils.RequestOptions{
			BaseURL:         baseURL,
			Path:            fmt.Sprintf("/nonexistent_%d.aspx", r.Intn(9e6)),
			Method:          common.HttpMethodGet,
			Params:          common.RequestParams{},
			Timeout:         timeout,
			FollowRedirects: false,
			Insecure:        true,
		})
		if nf.ResponseBody != nil {
			if v := parseIisVersionFromBody(*nf.ResponseBody); v != "" {
				site.Server = &enumerateWebserverFern.WebServerInfo{Name: "Microsoft-IIS", Version: &v}
			}
		}
	}

	// Capture auth schemes when 401
	if root.StatusCode != nil && *root.StatusCode == 401 {
		auths := utils.GetHeaderValues(&root, "WWW-Authenticate")
		if len(auths) > 0 {
			site.AuthenticationMethods = auths
		}
	}

	return site, reqs, errs
}

var iisRe = regexp.MustCompile(`(?i)(Microsoft-IIS)/(\d+\.\d+)`)

// parseBanners is a helper: banner & header parsing
func parseBanners(s *enumerateWebserverFern.IisSite, r *common.RequestInfo) {
	serverHdr := utils.GetHeader(r, "Server")
	if serverHdr != "" {
		if matches := iisRe.FindStringSubmatch(serverHdr); len(matches) > 2 {
			v := matches[2]
			s.Server = &enumerateWebserverFern.WebServerInfo{Name: "Microsoft-IIS", Version: &v}
		} else {
			s.Server = &enumerateWebserverFern.WebServerInfo{Name: serverHdr}
		}
	}

	// Get framework version from X-AspNet-Version
	aspVer := utils.GetHeader(r, "X-AspNet-Version")
	var version *string
	if aspVer != "" {
		version = &aspVer
	}

	// Get framework name from X-Powered-By
	if xp := utils.GetHeader(r, "X-Powered-By"); xp != "" {
		s.Frameworks = append(s.Frameworks, &enumerateWebserverFern.WebFrameworkInfo{Name: xp, Version: version})
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
