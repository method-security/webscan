package enumerate

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"

	webscan "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

// PerformAppEnumerateWebserverIIS is the main entry point for enumerating IIS targets.
func PerformAppEnumerateWebserverIIS(ctx context.Context, config *webscan.AppEnumerateIisConfig) webscan.AppEnumerateIisReport {
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

	// Semaphore to control concurrency
	semaphore := make(chan struct{}, maxGoroutines)

	// Process each target concurrently
	for _, target := range config.Targets {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire a "slot"

		go func(t string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release slot

			result, errs := scanTarget(t, config.Timeout, config)
			resultsChan <- &result
			if len(errs) > 0 {
				errorsChan <- errs
			}
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

	return report
}

// scanTarget checks a single target (URL) for IIS.
func scanTarget(target string, timeout int, config *webscan.AppEnumerateIisConfig) (webscan.AppEnumerateIisTargetInfo, []string) {
	result := webscan.AppEnumerateIisTargetInfo{
		Target: target,
	}

	var allErrors []string
	var allRequests []*common.RequestInfo

	// Directly check the site using the target URL
	site, reqs, errs := checkIISSite(target, timeout, config)
	if len(errs) > 0 {
		allErrors = append(allErrors, errs...)
	}

	// If we successfully enumerated anything, append results
	if site != nil {
		if result.Sites == nil {
			result.Sites = []*webscan.IisSite{}
		}
		result.Sites = append(result.Sites, site)
	}
	allRequests = append(allRequests, reqs...)

	result.Requests = allRequests
	return result, allErrors
}

// checkIISSite performs a simple HTTP(S) GET and extracts headers to populate IisSite.
func checkIISSite(targetURL string, timeout int, config *webscan.AppEnumerateIisConfig) (
	*webscan.IisSite,
	[]*common.RequestInfo,
	[]string,
) {
	var (
		site *webscan.IisSite
		errs []string
		reqs []*common.RequestInfo
	)

	// Parse the URL to get baseURL and path
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to parse URL %s: %v", targetURL, err))
		return nil, nil, errs
	}

	// Extract base URL (scheme + host) and path
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	reqInfo := utils.PerformRequestScan(baseURL, path, common.HttpMethodGet, common.RequestParams{}, timeout, true)

	// If we couldn't connect, return early
	if reqInfo.StatusCode == nil {
		errs = append(errs, fmt.Sprintf("request failed for %s - no response", targetURL))
		return nil, []*common.RequestInfo{&reqInfo}, errs
	}

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
			} else {
				// If regex didn't match but we know it's IIS, still set the server
				site.Server = &webscan.ServerInfo{
					Name: "Microsoft-IIS",
				}
			}
		} else {
			// Not an IIS server, just use the header as is
			site.Server = &webscan.ServerInfo{
				Name: serverName,
			}
		}

		// Check for PHP version in Server header (common in IIS configurations)
		rePhp := regexp.MustCompile(`PHP/(\d+\.\d+\.\d+|\d+\.\d+)`)
		if phpMatches := rePhp.FindStringSubmatch(serverHeader); len(phpMatches) > 1 {
			phpVersion := phpMatches[1]

			// Add PHP to frameworks if not already added
			addFramework(site, "PHP", &phpVersion)
		}
	}

	// Framework detection
	// 1. ASP.NET - Check X-AspNet-Version header
	aspnetVer := getHeader(&reqInfo, "X-AspNet-Version")
	if aspnetVer != "" {
		// Add ASP.NET to frameworks
		addFramework(site, "ASP.NET", &aspnetVer)
	}

	// 2. Plesk - Check for specific headers
	if getHeader(&reqInfo, "X-Powered-By-Plesk") != "" {
		addFramework(site, "Plesk", nil)
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
		}
	}

	// Check for Node.js/Express
	if getHeader(&reqInfo, "X-Powered-By") == "Express" ||
		strings.Contains(getHeader(&reqInfo, "X-Powered-By"), "Node") {
		addFramework(site, "Node.js", nil)
	}

	// Check for default documents if enabled
	if config.EnumDefaultDocuments != nil && *config.EnumDefaultDocuments {
		defaultDocs, docReqs := checkDefaultDocuments(baseURL, timeout)
		if len(defaultDocs) > 0 {
			site.DefaultDocuments = defaultDocs
		}
		reqs = append(reqs, docReqs...)
	}

	// If we had a 401, we might parse "WWW-Authenticate" headers to see auth methods
	if *reqInfo.StatusCode == 401 {
		authMethods := getHeaderValues(&reqInfo, "WWW-Authenticate")
		if len(authMethods) > 0 {
			site.AuthenticationMethods = authMethods
		}
	}

	reqs = append([]*common.RequestInfo{&reqInfo}, reqs...)
	return site, reqs, errs
}

// checkDefaultDocuments tries to access common default documents
func checkDefaultDocuments(baseURL string, timeout int) ([]string, []*common.RequestInfo) {
	// Common default documents in IIS
	potentialDefaults := []string{
		"Default.asp",
		"Default.aspx",
		"index.htm",
		"index.html",
		"iisstart.htm",
		"default.htm",
	}

	var foundDocs []string
	var requests []*common.RequestInfo

	for _, doc := range potentialDefaults {
		// Extract base URL and path
		path := "/" + doc

		// Make request
		reqInfo := utils.PerformRequestScan(baseURL, path, common.HttpMethodGet, common.RequestParams{}, timeout, true)
		requests = append(requests, &reqInfo)

		// If we got a 200 OK, it's likely a default document
		if reqInfo.StatusCode != nil && *reqInfo.StatusCode == 200 {
			foundDocs = append(foundDocs, doc)
		}
	}

	return foundDocs, requests
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
