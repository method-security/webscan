package saas

import (
	// Standard
	"context"
	"fmt"
	"log"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discoversaasfern "github.com/Method-Security/webscan/generated/go/discover/saas"

	// Internal
	discoversaasactivehelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createSendHTTPRequestConfig(baseURL, path string, config discoversaasfern.DiscoverSaasActiveConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       config.MaxRedirects,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func LaunchDiscoverSaasActive(ctx context.Context, config discoversaasfern.DiscoverSaasActiveConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*discoversaasfern.DiscoverSaasActiveReport, error) {
	// Initialize report
	report := discoversaasfern.DiscoverSaasActiveReport{
		Config: &config,
	}
	errors := []string{}

	// Process each organization
	attempts := []*discoversaasfern.SaasActiveAttempt{}
	for _, org := range config.Orgs {
		attempt := &discoversaasfern.SaasActiveAttempt{Org: org}
		companies := []*discoversaasfern.SaasActiveCompany{}

		// Process each company
		for company, fingerprint := range config.SaasFingerprints.Fingerprints {
			companyResult := &discoversaasfern.SaasActiveCompany{Company: company}
			requests := []*discoversaasfern.SaasActiveRequest{}

			// Process each domain slug
			for _, domainSlug := range fingerprint.DomainSlugs {
				// Determine the schemas to use for the request
				schemas := []string{"https"}
				if !config.HttpsOnly {
					schemas = append(schemas, "http")
				}

				// Process each schema
				for _, schema := range schemas {
					log.Printf("Processing company: %s in org: %s with schema: %s", company, org, schema)
					saasRequest := &discoversaasfern.SaasActiveRequest{}

					// Construct the full URL
					slug := strings.Replace(domainSlug, "INPUT_ORG", org, 1)
					fullURL := fmt.Sprintf("%s://%s", schema, slug)

					// Construct the full URL
					baseURL, path, err := requesthelpers.SplitTargetURL(fullURL)
					if err != nil {
						errors = append(errors, fmt.Sprintf("invalid address %s: %v", fullURL, err))
						continue
					}

					// Send the request
					httpConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
					httpRequestResponse, err := request.SendRequest(ctx, httpConfig)
					if err != nil {
						errors = append(errors, fmt.Sprintf("failed to probe %s: %s", fullURL, err))
						continue
					}
					saasRequest.Request = httpRequestResponse

					// Analyze the request
					redirectedPage := len(httpRequestResponse.Response.RedirectChain) > 1
					finding := discoversaasactivehelpers.AnalyzeSaasRequest(ctx, saasRequest, fingerprint, config.SsoFingerprints, redirectedPage)
					saasRequest.Findings = finding

					// Add request if it meets our criteria
					if discoversaasactivehelpers.ShouldAddRequest(saasRequest, config.SuccessfulOnly) {
						requests = append(requests, saasRequest)
					}
				}
			}

			companyResult.Requests = requests
			companies = append(companies, companyResult)
		}

		attempt.Companies = companies
		attempts = append(attempts, attempt)
	}

	report.Orgs = attempts
	report.Errors = errors
	return &report, nil
}
