package saas

import (
	// Standard
	"context"
	"log"
	"strings"

	// Generated
	discover "github.com/Method-Security/webscan/generated/go/discover"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// AnalyzeSaasRequest analyzes a SaaS request and returns a finding
func AnalyzeSaasRequest(ctx context.Context, request *discover.SaasActiveRequest, saasFingerprint *discover.SaasFingerprintEntry, selectedSsoFingerprints *discover.SaasFingerprintFile, redirectedPage bool) *discover.SaasActiveFinding {
	log := svc1log.FromContext(ctx)
	// Initial validation
	// Note: If no response body or headers, or status code is not 200, return false
	if (request.Request == nil && request.Request.Response == nil && request.Request.Response.ResponseHeaders == nil) ||
		(request.Request == nil || request.Request.Response == nil || request.Request.Response.StatusCode == nil || *request.Request.Response.StatusCode != 200) {
		return nil
	}

	if saasFingerprint.FingerprintProfile == nil {
		log.Warn("No fingerprint profile found",
			svc1log.SafeParam("baseUrl", request.Request.Request.BaseUrl),
			svc1log.SafeParam("path", request.Request.Request.Path))
		return nil
	}

	// Initialize values
	companyPage := false
	finding := &discover.SaasActiveFinding{CompanyPage: &companyPage}

	// Check for indicators that the webpage is not actually a valid SaaS page
	// Note: Sometimes it will appear as a SaaS page but strings such as 'Not found' or '404' will be present
	responseBodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(request.Request.Response.ResponseBody)
	if isFalsePositive(responseBodyStr, &saasFingerprint.FingerprintProfile.PageNotFound) {
		return finding
	}

	// Check for SSO Page first
	// Note: SSO pages are only found if we have redirected to a new page from the intial SaaS page request
	if redirectedPage {
		for ssoCompany, ssoFingerprint := range selectedSsoFingerprints.Fingerprints {
			if ssoFingerprint.FingerprintProfile == nil {
				continue
			}

			if checkHeaders(ctx, request.Request.Response.ResponseHeaders, ssoFingerprint.FingerprintProfile.Headers) {
				finding.SsoPage = &ssoCompany
				break
			}
			// Check body if no header match
			if checkBody(ctx, responseBodyStr, ssoFingerprint.FingerprintProfile.Body) {
				finding.SsoPage = &ssoCompany
				break
			}
		}
	}

	// Check for Company Page
	if finding.SsoPage == nil {
		if checkHeaders(ctx, request.Request.Response.ResponseHeaders, saasFingerprint.FingerprintProfile.Headers) {
			companyPage = true
			finding.CompanyPage = &companyPage
		}
		// Check for company match in body if not already found
		if !companyPage && checkBody(ctx, responseBodyStr, saasFingerprint.FingerprintProfile.Body) {
			companyPage = true
			finding.CompanyPage = &companyPage
		}
	}

	return finding
}

// isFalsePositive is a helper function to check for false positives
func isFalsePositive(responseBody *string, notFoundPatterns *[]string) bool {
	if responseBody == nil {
		return false
	}

	if notFoundPatterns == nil {
		log.Printf("[WARNING] No 'not found patterns' found for %s", *responseBody)
		return false
	}

	bodyLower := strings.ToLower(*responseBody)
	for _, pattern := range *notFoundPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// checkHeaders is a helper function to check headers for matches
func checkHeaders(ctx context.Context, headers map[string][]string, fingerprintHeaders map[string][]string) bool {
	log := svc1log.FromContext(ctx)
	if headers == nil || fingerprintHeaders == nil {
		return false
	}

	for fingerprintHeader, fingerprintValue := range fingerprintHeaders {
		// Normalize header key to lowercase for case-insensitive comparison
		for headerKey, headerValue := range headers {
			if strings.EqualFold(fingerprintHeader, headerKey) {
				// If the fingerprint value is empty or matches (case insensitive)
				if len(fingerprintValue) == 0 {
					return true
				}
				for _, fingerprintValue := range fingerprintValue {
					for _, headerValue := range headerValue {
						if strings.EqualFold(fingerprintValue, headerValue) {
							log.Debug("Header match found", svc1log.SafeParam("header", fingerprintHeader), svc1log.SafeParam("value", headerValue))
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// checkBody is a helper function to check body for matches
func checkBody(ctx context.Context, responseBody *string, fingerprintBody []string) bool {
	log := svc1log.FromContext(ctx)
	if responseBody == nil {
		return false
	}

	bodyLower := strings.ToLower(*responseBody)
	for _, bodyEntry := range fingerprintBody {
		if strings.Contains(bodyLower, strings.ToLower(bodyEntry)) {
			log.Debug("Body match found", svc1log.SafeParam("pattern", bodyEntry))
			return true
		}
	}
	return false
}
