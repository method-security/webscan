package saas

import (
	// Standard
	"context"
	"fmt"
	"log"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoversaasactivehelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"
	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
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

func LaunchDiscoverSaasActive(ctx context.Context, config discover.DiscoverSaasConfig, saasFingerprints discover.SaasFingerprintFile, ssoFingerprints discover.SaasFingerprintFile, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*discover.DiscoverSaasReport, error) {
	// Initialize report
	report := discover.DiscoverSaasReport{
		Config: &config,
	}
	errors := []string{}

	// Process each organization
	attempts := []*discover.SaasActiveAttempt{}
	for _, org := range config.Orgs {
		attempt := &discover.SaasActiveAttempt{Org: org}
		companies := []*discover.SaasActiveCompany{}

		// Process each company
		for company, fingerprint := range saasFingerprints.Fingerprints {
			companyResult := &discover.SaasActiveCompany{Company: company}
			requests := []*discover.SaasActiveRequest{}

			// Process each domain slug
			for _, domainSlug := range fingerprint.DomainSlugs {
				// Determine the schemas to use for the request
				schemas := []string{"https"}
				schemas = append(schemas, "http")

				// Process each schema
				for _, schema := range schemas {
					log.Printf("Processing company: %s in org: %s with schema: %s", company, org, schema)
					saasRequest := &discover.SaasActiveRequest{}

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
					finding := discoversaasactivehelpers.AnalyzeSaasRequest(ctx, saasRequest, fingerprint, &ssoFingerprints, redirectedPage)
					saasRequest.Findings = finding

					// Add request if it meets our criteria
					if discoversaasactivehelpers.ShouldAddRequest(saasRequest) {
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

	report.Result = &discover.DiscoverSaasResult{Orgs: attempts}
	report.Errors = errors
	return &report, nil
}
