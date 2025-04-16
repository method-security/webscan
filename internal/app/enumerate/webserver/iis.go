package enumerate

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	enumerateWebserverFern "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	common "github.com/Method-Security/webscan/generated/go/common"
)

// PerformAppEnumerateWebserverIIS is the main entry point for enumerating IIS targets.
func PerformAppEnumerateWebserverIIS(ctx context.Context, config *enumerateWebserverFern.AppEnumerateIisConfig) enumerateWebserverFern.AppEnumerateIisReport {
	report := enumerateWebserverFern.AppEnumerateIisReport{Config: config}

	// Channels for results and errors
	resultsChan := make(chan *enumerateWebserverFern.AppEnumerateIisTargetInfo, len(config.Targets))
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

			result, errs := scanTarget(t, config.Timeout)
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
	var targetResults []*enumerateWebserverFern.AppEnumerateIisTargetInfo
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

// scanTarget checks a single target (hostname or IP) for IIS over common ports, e.g., 80/443.
func scanTarget(target string, timeout int) (enumerateWebserverFern.AppEnumerateIisTargetInfo, []string) {
	result := enumerateWebserverFern.AppEnumerateIisTargetInfo{
		Target: target,
	}

	var allErrors []string

	// In a black-box scenario, we typically check known HTTP ports
	portsToCheck := []int{80, 443}
	for _, port := range portsToCheck {
		isHTTPS := (port == 443)

		site, bindings, errs := checkIISSite(target, port, timeout, isHTTPS)
		if len(errs) > 0 {
			allErrors = append(allErrors, errs...)
			continue
		}

		// If we successfully enumerated anything, append results
		if len(bindings) > 0 {
			if result.Bindings == nil {
				result.Bindings = []*enumerateWebserverFern.IisBinding{}
			}
			result.Bindings = append(result.Bindings, bindings...)
		}
		if site != nil {
			if result.Sites == nil {
				result.Sites = []*enumerateWebserverFern.IisSite{}
			}
			result.Sites = append(result.Sites, site)
		}
	}

	return result, allErrors
}

// checkIISSite performs a simple HTTP(S) GET and extracts headers to populate IisSite and IisBinding.
func checkIISSite(host string, port, timeout int, isHTTPS bool) (
	*enumerateWebserverFern.IisSite,
	[]*enumerateWebserverFern.IisBinding,
	[]string,
) {
	var (
		site     *enumerateWebserverFern.IisSite
		bindings []*enumerateWebserverFern.IisBinding
		errs     []string
	)

	protocol := common.WebProtocolHttp
	if isHTTPS {
		protocol = common.WebProtocolHttps
	}

	// Construct URL
	url := fmt.Sprintf("%s://%s:%d/", strings.ToLower(string(protocol)), host, port)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// If HTTPS, set up TLS config
	if isHTTPS {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // for scanning; not recommended in prod
				ServerName:         host, // SNI
			},
		}
		client.Transport = tr
	}

	// Make a simple GET request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to create request: %v", err))
		return nil, nil, errs
	}

	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, fmt.Sprintf("request failed for %s:%d - %v", host, port, err))
		return nil, nil, errs
	}
	defer resp.Body.Close()

	// Populate one binding (in black-box, we may only have partial info)
	binding := &enumerateWebserverFern.IisBinding{
		Hostname: host,
		Port:     port,
		Protocol: protocol,
		Ssl:      isHTTPS,
		Ip:       "", // Possibly do a DNS lookup or track ephemeral
		Sni:      isHTTPS,
	}
	// For demonstration, we'll keep certificate info minimal
	if isHTTPS && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		var certInfo []string
		for _, cert := range resp.TLS.PeerCertificates {
			summary := fmt.Sprintf("Subject=%s;Issuer=%s;NotAfter=%s",
				cert.Subject.String(), cert.Issuer.String(), cert.NotAfter.Format(time.RFC3339))
			certInfo = append(certInfo, summary)
		}
		if len(certInfo) > 0 {
			binding.CertificateInfo = certInfo
		}
	}
	bindings = append(bindings, binding)

	// Build a site object
	site = &enumerateWebserverFern.IisSite{
		Hostname:          host,
		Path:              "/", // We only tested root
		DirectoryBrowsing: false,
		// You can fill other optional fields below
	}

	if srv := resp.Header.Get("Server"); srv != "" {
		site.ServerHeader = &srv
		// Extract IIS version number
		if strings.Contains(strings.ToLower(srv), "microsoft-iis") {
			re := regexp.MustCompile(`Microsoft-IIS/(\d+\.\d+)`)
			if matches := re.FindStringSubmatch(srv); len(matches) > 1 {
				version := matches[1]
				site.ServerVersion = &version
			}
		}
	}

	// Get ASP.NET version from X-AspNet-Version header
	if aspnetVer := resp.Header.Get("X-AspNet-Version"); aspnetVer != "" {
		site.AspnetVersion = &aspnetVer
	}

	// Get frameworks from X-Powered-By header
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		frameworks := []string{xpb}
		site.Frameworks = frameworks
	}

	// Check for directory browsing (super naive).
	// Typically you'd check if requesting a known directory returns a listing
	// For now, we set false. See prior snippet for how to implement a real check.
	site.DirectoryBrowsing = false

	// If we had a 401, we might parse "WWW-Authenticate" headers to see auth methods
	if resp.StatusCode == http.StatusUnauthorized {
		authMethods := resp.Header.Values("WWW-Authenticate")
		if len(authMethods) > 0 {
			site.AuthenticationMethods = authMethods
		}
	}

	return site, bindings, errs
}
