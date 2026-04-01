package saas

import (
	// Standard
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverpagehelpers "github.com/Method-Security/webscan/internal/discover/page/helpers"
	discoversaashelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	"github.com/Method-Security/webscan/utils/request/headless"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	rod "github.com/go-rod/rod"
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

// createSharedBrowser creates and configures a shared browser instance for reuse across requests
func createSharedBrowser(ctx context.Context, config discover.DiscoverSaasConfig) (*rod.Browser, error) {
	log := svc1log.FromContext(ctx)

	// Create a headless requester to use its initialization logic
	requester := headless.NewRequester(config.Timeout, config.HeadlessConfig)
	err := requester.InitializeBrowser(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize browser: %v", err)
	}

	log.Info("Shared browser instance created and configured")
	return requester.Browser, nil
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

	// Create a single browser instance for reuse if using headless method
	var sharedBrowser *rod.Browser
	if config.RequestMethod == common.RequestMethodHeadless {
		log.Info("Creating shared browser instance for headless requests")

		var err error
		sharedBrowser, err = createSharedBrowser(ctx, config)
		if err != nil {
			return nil, err
		}

		// Store browser in config for reuse
		config.HeadlessConfig.Browser = sharedBrowser
	}

	// Ensure browser cleanup
	defer func() {
		if sharedBrowser != nil {
			log.Info("Closing shared browser instance")
			if err := sharedBrowser.Close(); err != nil {
				log.Warn("Failed to close shared browser", svc1log.SafeParam("error", err.Error()))
			}
		}
	}()

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
				schemas := []string{"https"}

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
						baseURL, path, _, err := requesthelpers.SplitTargetURL(fullURL)
						if err != nil {
							errorsMutex.Lock()
							errors = append(errors, fmt.Sprintf("invalid address %s: %v", fullURL, err))
							errorsMutex.Unlock()
							return
						}

						// Send the request using the shared browser
						httpConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
						httpRequestResponse, err := request.SendRequest(ctx, httpConfig)
						if err != nil {
							errorsMutex.Lock()
							errors = append(errors, fmt.Sprintf("failed to probe %s: %s", fullURL, err))
							errorsMutex.Unlock()
							return
						}
						saasRequest.Request = httpRequestResponse

						// Apply stealth delay between requests
						if config.Sleep > 0 {
							delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
							time.Sleep(delay)
						}

						// Analyze the request
						saasRequest.Findings = discoversaashelpers.AnalyzeSaasRequest(ctx, saasRequest, fingerprint, &ssoFingerprints)

						// Add request if company or sso page is found (Positive hit)
						if discoversaashelpers.ShouldAddRequest(saasRequest) {
							// Capture screenshot for positive hits if using headless method
							if config.RequestMethod == common.RequestMethodHeadless && sharedBrowser != nil {
								log.Info("Capturing screenshot for positive hit", svc1log.SafeParam("url", fullURL))

								// Create a headless requester with the shared browser for screenshot
								screenshotRequester := &headless.Requester{
									Browser:                    sharedBrowser,
									TimeoutSeconds:             config.Timeout,
									MinDOMStabalizeTimeSeconds: config.HeadlessConfig.MinDomStabalizeTime,
								}

								screenshotBytes, err := discoverpagehelpers.CaptureScreenshot(ctx, screenshotRequester, &httpConfig)
								if err != nil {
									log.Warn("Failed to capture screenshot", svc1log.SafeParam("url", fullURL), svc1log.SafeParam("error", err.Error()))
								} else {
									saasRequest.Screenshot = &screenshotBytes
									log.Info("Screenshot captured successfully", svc1log.SafeParam("url", fullURL))
								}
							}

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
