package saas

import (
	// Standard
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoversaashelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func createSendHTTPRequestConfig(baseURL, path string, config discover.DiscoverSaasConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       config.MaxRedirects,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func LaunchDiscoverSaas(ctx context.Context, config discover.DiscoverSaasConfig, saasFingerprints discover.SaasFingerprintFile, ssoFingerprints discover.SaasFingerprintFile, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*discover.DiscoverSaasReport, error) {
	// Get the logger from the context
	log := svc1log.FromContext(ctx)

	// Initialize report
	report := discover.DiscoverSaasReport{
		Config: &config,
	}

	// Use mutexes to protect shared data
	var errorsMutex sync.Mutex
	errors := []string{}

	// Determine number of concurrent goroutines
	maxGoroutines := runtime.GOMAXPROCS(0) // Default to number of CPUs
	if config.Threads > 0 {
		maxGoroutines = config.Threads
	}

	// Create a semaphore to limit concurrent goroutines
	semaphore := make(chan struct{}, maxGoroutines)

	log.Info("Starting SaaS discovery", svc1log.SafeParam("maxConcurrency", maxGoroutines))

	// Process each organization
	attempts := []*discover.SaasActiveAttempt{}
	for _, org := range config.Orgs {
		attempt := &discover.SaasActiveAttempt{Org: org}
		companies := []*discover.SaasActiveCompany{}

		// Process each company
		for company, fingerprint := range saasFingerprints.Fingerprints {
			companyResult := &discover.SaasActiveCompany{Company: company}

			// Use channel to collect requests and WaitGroup for synchronization
			requestsChan := make(chan *discover.SaasActiveRequest, len(fingerprint.DomainSlugs)*2) // *2 for http/https
			var wg sync.WaitGroup

			// Process each domain slug
			for _, domainSlug := range fingerprint.DomainSlugs {
				// Determine the schemas to use for the request
				schemas := []string{"https", "http"}

				// Process each schema with controlled concurrency
				for _, schema := range schemas {
					wg.Add(1)

					// Acquire semaphore (blocks if maxGoroutines are running)
					semaphore <- struct{}{}

					go func(domainSlug, schema string) {
						defer wg.Done()
						defer func() { <-semaphore }() // Release semaphore when done

						log.Info("Processing company", svc1log.SafeParam("company", company), svc1log.SafeParam("org", org), svc1log.SafeParam("schema", schema))
						saasRequest := &discover.SaasActiveRequest{}

						// Construct the full URL
						slug := strings.Replace(domainSlug, "INPUT_ORG", org, 1)
						fullURL := fmt.Sprintf("%s://%s", schema, slug)

						// Construct the full URL
						baseURL, path, err := requesthelpers.SplitTargetURL(fullURL)
						if err != nil {
							errorsMutex.Lock()
							errors = append(errors, fmt.Sprintf("invalid address %s: %v", fullURL, err))
							errorsMutex.Unlock()
							return
						}

						// Send the request
						httpConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
						httpRequestResponse, err := request.SendRequest(ctx, httpConfig)
						if err != nil {
							errorsMutex.Lock()
							errors = append(errors, fmt.Sprintf("failed to probe %s: %s", fullURL, err))
							errorsMutex.Unlock()
							return
						}
						saasRequest.Request = httpRequestResponse

						// Analyze the request
						saasRequest.Findings = discoversaashelpers.AnalyzeSaasRequest(ctx, saasRequest, fingerprint, &ssoFingerprints)

						// Add request if company or sso page is found (Positive hit)
						if discoversaashelpers.ShouldAddRequest(saasRequest) {
							requestsChan <- saasRequest
						}
					}(domainSlug, schema)
				}
			}

			// Wait for all goroutines to complete and close the channel
			go func() {
				wg.Wait()
				close(requestsChan)
			}()

			// Collect all requests from the channel
			requests := []*discover.SaasActiveRequest{}
			for req := range requestsChan {
				requests = append(requests, req)
			}

			// Dont add if no data
			if len(requests) > 0 {
				companyResult.Requests = requests
				companies = append(companies, companyResult)
			}
		}

		// Dont add if no data
		if len(companies) > 0 {
			attempt.Companies = companies
			attempts = append(attempts, attempt)
		}
	}

	report.Result = &discover.DiscoverSaasResult{Orgs: attempts}
	report.Errors = errors
	return &report, nil
}
