package enumerate

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

// PerformAppEnumerateWebserverIIS is the main entry point for enumerating IIS targets.
func PerformAppEnumerateWebserverIIS(ctx context.Context, config *webscan.AppEnumerateIisConfig) webscan.AppEnumerateIisReport {
	startTime := time.Now()
	log.Printf("[DEBUG] Starting IIS enumeration with %d targets", len(config.Targets))

	report := webscan.AppEnumerateIisReport{Config: config}

	// Channels for results and errors
	resultsChan := make(chan *webscan.AppEnumerateIisTargetInfo, len(config.Targets))
	errorsChan := make(chan []string, len(config.Targets))

	// WaitGroup to wait for all goroutines
	var wg sync.WaitGroup

	// Concurrency limit (defaults to number of CPUs if Threads not set)
	maxGoroutines := runtime.GOMAXPROCS(0)
	if config.Threads != nil {
		maxGoroutines = *config.Threads
	}
	log.Printf("[DEBUG] Using %d concurrent threads for scanning", maxGoroutines)

	// Semaphore to control concurrency
	semaphore := make(chan struct{}, maxGoroutines)

	// Process each target concurrently
	for _, target := range config.Targets {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire a "slot"

		go func(t string) {
			targetStartTime := time.Now()
			log.Printf("[DEBUG] Starting scan for target: %s", t)

			defer wg.Done()
			defer func() { <-semaphore }() // Release slot

			result, errs := scanTarget(t, config.Timeout)
			resultsChan <- &result
			if len(errs) > 0 {
				errorsChan <- errs
			}

			log.Printf("[DEBUG] Completed scan for target: %s in %s", t, time.Since(targetStartTime))
		}(target)
	}

	// Wait for all goroutines
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect results and errors
	var targetResults []*webscan.AppEnumerateIisTargetInfo
	var errors []string

	for result := range resultsChan {
		targetResults = append(targetResults, result)
	}

	for errs := range errorsChan {
		errors = append(errors, errs...)
	}

	report.Errors = errors
	report.Targets = targetResults

	log.Printf("[DEBUG] IIS enumeration completed in %s. Found %d results with %d errors",
		time.Since(startTime), len(targetResults), len(errors))

	return report
}

// scanTarget checks a single target (URL) for IIS.
func scanTarget(target string, timeout int) (webscan.AppEnumerateIisTargetInfo, []string) {
	startTime := time.Now()
	log.Printf("[DEBUG] Scanning target URL: %s", target)

	result := webscan.AppEnumerateIisTargetInfo{
		Target: target,
	}

	var allErrors []string
	var allRequests []*common.RequestInfo

	// Directly check the site using the target URL
	site, reqs, errs := checkIISSite(target, timeout)
	if len(errs) > 0 {
		allErrors = append(allErrors, errs...)
		log.Printf("[DEBUG] Errors checking target %s: %v", target, errs)
	}

	// If we successfully enumerated anything, append results
	if site != nil {
		if result.Sites == nil {
			result.Sites = []*webscan.IisSite{}
		}
		result.Sites = append(result.Sites, site)
		log.Printf("[DEBUG] Found IIS site at URL: %s", target)
	}
	allRequests = append(allRequests, reqs...)

	log.Printf("[DEBUG] Completed scan for target URL %s in %s. Found %d sites with %d requests",
		target, time.Since(startTime), len(result.Sites), len(allRequests))

	result.Requests = allRequests
	return result, allErrors
}

// checkIISSite performs a simple HTTP(S) GET and extracts headers to populate IisSite.
func checkIISSite(targetURL string, timeout int) (
	*webscan.IisSite,
	[]*common.RequestInfo,
	[]string,
) {
	startTime := time.Now()
	log.Printf("[DEBUG] Checking IIS site: %s", targetURL)

	var (
		site *webscan.IisSite
		errs []string
	)

	log.Printf("[DEBUG] Using URL: %s", targetURL)

	// Extract base URL and path
	path := "/"
	baseURL := targetURL

	// Find the first "/" after the scheme and domain
	// Start searching after "http://" or "https://"
	schemeEndPos := strings.Index(targetURL, "://")
	if schemeEndPos != -1 {
		prefixLen := schemeEndPos + 3 // Length of "://" is 3

		// Make sure the URL is long enough
		if len(targetURL) > prefixLen {
			if idx := strings.Index(targetURL[prefixLen:], "/"); idx > 0 {
				baseURL = targetURL[:idx+prefixLen]
				path = targetURL[idx+prefixLen:]
			}
		}
	}

	log.Printf("[DEBUG] Using baseURL: %s, path: %s", baseURL, path)

	// Make a simple GET request using utils.PerformRequestScan
	requestStartTime := time.Now()
	log.Printf("[DEBUG] Starting HTTP request to %s", targetURL)

	reqInfo := utils.PerformRequestScan(baseURL, path, common.HttpMethodGet, common.RequestParams{}, timeout, true)
	log.Printf("[DEBUG] PerformRequestScan completed in %s with status: %d",
		time.Since(requestStartTime), reqInfo.StatusCode)

	// If we couldn't connect, return early
	if reqInfo.StatusCode == nil {
		errs = append(errs, fmt.Sprintf("request failed for %s - no response", targetURL))
		log.Printf("[DEBUG] HTTP request error: no response")
		return nil, []*common.RequestInfo{&reqInfo}, errs
	}

	// Build a site object
	processingStartTime := time.Now()
	log.Printf("[DEBUG] Processing response headers")

	site = &webscan.IisSite{}

	// Check server header for IIS and possibly embedded framework info
	serverHeader := getHeader(&reqInfo, "Server")
	if serverHeader != "" {
		// Create ServerInfo structure
		serverName := serverHeader

		// Extract IIS version number and clean server name
		if strings.Contains(strings.ToLower(serverHeader), "microsoft-iis") {
			re := regexp.MustCompile(`(Microsoft-IIS)/(\d+\.\d+)`)
			if matches := re.FindStringSubmatch(serverHeader); len(matches) > 2 {
				serverName = matches[1] // Just "Microsoft-IIS" without version
				version := matches[2]
				site.Server = &webscan.ServerInfo{
					Name:    serverName,
					Version: &version,
				}
				log.Printf("[DEBUG] Extracted server name: %s, version: %s", serverName, version)
			} else {
				// If regex didn't match but we know it's IIS, still set the server
				site.Server = &webscan.ServerInfo{
					Name: "Microsoft-IIS",
				}
				log.Printf("[DEBUG] Found IIS server, but couldn't extract version")
			}
		} else {
			// Not an IIS server, just use the header as is
			site.Server = &webscan.ServerInfo{
				Name: serverName,
			}
			log.Printf("[DEBUG] Found non-IIS Server header: %s", serverName)
		}

		// Check for PHP version in Server header (common in IIS configurations)
		rePhp := regexp.MustCompile(`PHP/(\d+\.\d+\.\d+|\d+\.\d+)`)
		if phpMatches := rePhp.FindStringSubmatch(serverHeader); len(phpMatches) > 1 {
			phpVersion := phpMatches[1]

			// Add PHP to frameworks if not already added
			addFramework(site, "PHP", &phpVersion)
			log.Printf("[DEBUG] Detected PHP version %s from Server header", phpVersion)
		}
	}

	// Framework detection
	// 1. ASP.NET - Check X-AspNet-Version header
	aspnetVer := getHeader(&reqInfo, "X-AspNet-Version")
	if aspnetVer != "" {
		// Add ASP.NET to frameworks
		addFramework(site, "ASP.NET", &aspnetVer)
		log.Printf("[DEBUG] Found ASP.NET version: %s", aspnetVer)
	}

	// 2. Plesk - Check for specific headers
	if getHeader(&reqInfo, "X-Powered-By-Plesk") != "" {
		addFramework(site, "Plesk", nil)
		log.Printf("[DEBUG] Detected Plesk framework")
	}

	// 3. Check for other frameworks in X-Powered-By header
	xpb := getHeader(&reqInfo, "X-Powered-By")
	if xpb != "" {
		// Split by commas if multiple values
		parts := strings.Split(xpb, ",")

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			// Common patterns: ASP.NET, PHP/7.4.1, JBoss-5.0/jbossas-5.0.5.Final
			framework := part
			var version *string

			// Try to extract version if in format "Framework/X.Y.Z"
			if slash := strings.Index(part, "/"); slash > 0 {
				framework = part[:slash]
				versionStr := part[slash+1:]
				version = &versionStr
			}

			addFramework(site, framework, version)

			if version != nil {
				log.Printf("[DEBUG] Added %s framework with version %s from X-Powered-By",
					framework, *version)
			} else {
				log.Printf("[DEBUG] Added %s framework from X-Powered-By", framework)
			}
		}

		log.Printf("[DEBUG] Found frameworks in X-Powered-By: %s", xpb)
	}

	// Check for Node.js/Express
	if getHeader(&reqInfo, "X-Powered-By") == "Express" ||
		strings.Contains(getHeader(&reqInfo, "X-Powered-By"), "Node") {
		addFramework(site, "Node.js", nil)
		log.Printf("[DEBUG] Detected Node.js framework")
	}

	// Check for custom errors
	if *reqInfo.StatusCode >= 400 {
		customErrors := true
		site.CustomErrors = &customErrors
		log.Printf("[DEBUG] Detected custom errors (status code: %d)", *reqInfo.StatusCode)
	}

	// If we had a 401, we might parse "WWW-Authenticate" headers to see auth methods
	if *reqInfo.StatusCode == 401 {
		authMethods := getHeaderValues(&reqInfo, "WWW-Authenticate")
		if len(authMethods) > 0 {
			site.AuthenticationMethods = authMethods
			log.Printf("[DEBUG] Found authentication methods: %v", authMethods)
		}
	}

	log.Printf("[DEBUG] Completed header processing in %s", time.Since(processingStartTime))
	log.Printf("[DEBUG] Completed IIS site check for %s in %s",
		targetURL, time.Since(startTime))

	return site, []*common.RequestInfo{&reqInfo}, errs
}

// Helper function to add a framework to the site if it doesn't already exist
func addFramework(site *webscan.IisSite, name string, version *string) {
	// Initialize if needed
	if site.Frameworks == nil {
		site.Frameworks = []*webscan.FrameworkInfo{}
	}

	// Check if framework already exists
	for _, f := range site.Frameworks {
		if strings.EqualFold(f.Name, name) {
			return // Already exists
		}
	}

	// Add the framework
	framework := &webscan.FrameworkInfo{
		Name: name,
	}
	if version != nil {
		framework.Version = version
	}

	site.Frameworks = append(site.Frameworks, framework)
}

// Helper function to safely get a header value from RequestInfo
func getHeader(req *common.RequestInfo, name string) string {
	if req.ResponseHeaders == nil {
		return ""
	}

	value, exists := req.ResponseHeaders[name]
	if exists {
		return value
	}

	// Try case-insensitive match
	for headerName, headerValue := range req.ResponseHeaders {
		if strings.EqualFold(headerName, name) {
			return headerValue
		}
	}

	return ""
}

// Helper function to get all values for a header from RequestInfo
func getHeaderValues(req *common.RequestInfo, name string) []string {
	if req.ResponseHeaders == nil {
		return nil
	}

	// In the current struct, we don't have a way to get multiple values for the same header
	// So we'll just return a single value if found
	value := getHeader(req, name)
	if value != "" {
		return []string{value}
	}

	return nil
}
