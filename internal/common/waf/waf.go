package waf

import (
	"strings"
	// Generated structs from Fern
	wafcommon "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

const (
	headerConfidence = 90
	bodyConfidence   = 70
)

type headerFingerprint struct {
	name                        string
	values                      []string
	needsStatusCodeConfirmation bool
	confidence                  int
}

type wafFingerprintRule struct {
	fingerprint wafcommon.WafFingerprint
	headers     []headerFingerprint
}

type wafMatch struct {
	fingerprint               *wafcommon.WafFingerprint
	matchedHeaders            []string
	matchedServerHeaderValues []string
	matchedBodyPatterns       []string
	confidence                int
}

// These rules intentionally favor precision over recall. CDN, cloud-platform,
// tracing, cache, and generic server headers are not evidence that a WAF is enabled.
var wafFingerprintRules = []wafFingerprintRule{
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumAkamai,
			Headers:            []string{},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "access denied - akamai", NeedsStatusCodeConfirmation: true},
				{Pattern: "akamai reference", NeedsStatusCodeConfirmation: true},
			},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumAws,
			Headers:            []string{"x-amzn-waf-action"},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "request blocked by aws waf", NeedsStatusCodeConfirmation: true},
			},
		},
		headers: []headerFingerprint{
			{name: "x-amzn-waf-action", values: []string{"captcha", "challenge"}, confidence: 100},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumAzure,
			Headers:            []string{"x-azure-waf-connection-id"},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "request blocked by azure waf", NeedsStatusCodeConfirmation: true},
				{Pattern: "azure web application firewall", NeedsStatusCodeConfirmation: true},
			},
		},
		headers: []headerFingerprint{
			{name: "x-azure-waf-connection-id", needsStatusCodeConfirmation: true},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumCloudflare,
			Headers:            []string{"cf-mitigated"},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "attention required! | cloudflare", NeedsStatusCodeConfirmation: true},
				{Pattern: "cloudflare's security service", NeedsStatusCodeConfirmation: true},
			},
		},
		headers: []headerFingerprint{
			{name: "cf-mitigated", values: []string{"challenge"}, confidence: 100},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumF5,
			Headers:            []string{"x-f5-waf-event-id", "x-f5-waf-transaction"},
			ServerHeaderValues: []string{},
			Body:               []*wafcommon.WafBody{},
		},
		headers: []headerFingerprint{
			{name: "x-f5-waf-event-id", needsStatusCodeConfirmation: true},
			{name: "x-f5-waf-transaction", needsStatusCodeConfirmation: true},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumGcp,
			Headers:            []string{},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "request denied by cloud armor", NeedsStatusCodeConfirmation: true},
			},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumIncapsula,
			Headers:            []string{"incapsula-incident-id"},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "incapsula incident id", NeedsStatusCodeConfirmation: true},
				{Pattern: "_incapsula_resource", NeedsStatusCodeConfirmation: true},
			},
		},
		headers: []headerFingerprint{
			{name: "incapsula-incident-id", needsStatusCodeConfirmation: true},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumOracle,
			Headers:            []string{"x-oracle-waf-connection-id"},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "oracle cloud infrastructure web application firewall", NeedsStatusCodeConfirmation: true},
				{Pattern: "oracle cloud infrastructure waf", NeedsStatusCodeConfirmation: true},
			},
		},
		headers: []headerFingerprint{
			{name: "x-oracle-waf-connection-id", needsStatusCodeConfirmation: true},
		},
	},
	{
		fingerprint: wafcommon.WafFingerprint{
			Provider:           wafcommon.WafProviderEnumSucuri,
			Headers:            []string{"sucuri-firewall"},
			ServerHeaderValues: []string{},
			Body: []*wafcommon.WafBody{
				{Pattern: "access denied - sucuri website firewall", NeedsStatusCodeConfirmation: true},
				{Pattern: "sucuri website firewall - not allowed", NeedsStatusCodeConfirmation: true},
			},
		},
		headers: []headerFingerprint{
			{name: "sucuri-firewall", needsStatusCodeConfirmation: true},
		},
	},
}

var blockedStatusCodes = map[int]struct{}{
	400: {},
	401: {},
	403: {},
	405: {},
	406: {},
	412: {},
	429: {},
}

func isBlockedStatusCode(statusCode *int) bool {
	if statusCode == nil {
		return false
	}
	_, exists := blockedStatusCodes[*statusCode]
	return exists
}

// FingerprintApplicationFirewall identifies high-confidence evidence that a
// response was produced or challenged by a WAF. Infrastructure-only evidence
// such as CDN headers is deliberately ignored.
func FingerprintApplicationFirewall(responseBody *string, responseHeaders map[string]string, statusCode *int) *wafcommon.WafFingerprint {
	headers := make(map[string][]string, len(responseHeaders))
	for name, value := range responseHeaders {
		headers[name] = []string{value}
	}

	match := fingerprintApplicationFirewall(responseBody, headers, statusCode)
	if match == nil {
		return nil
	}
	return match.fingerprint
}

func fingerprintApplicationFirewall(responseBody *string, responseHeaders map[string][]string, statusCode *int) *wafMatch {
	processedHeaders := normalizeHeaders(responseHeaders)
	responseBodyLower := ""
	if responseBody != nil {
		responseBodyLower = strings.ToLower(*responseBody)
	}

	var bestMatch *wafMatch
	ambiguous := false
	for i := range wafFingerprintRules {
		candidate := matchRule(&wafFingerprintRules[i], responseBodyLower, processedHeaders, statusCode)
		if candidate == nil {
			continue
		}
		if bestMatch == nil || candidate.confidence > bestMatch.confidence {
			bestMatch = candidate
			ambiguous = false
			continue
		}
		if candidate.confidence == bestMatch.confidence && candidate.fingerprint.Provider != bestMatch.fingerprint.Provider {
			ambiguous = true
		}
	}

	if ambiguous {
		return nil
	}
	return bestMatch
}

func matchRule(rule *wafFingerprintRule, responseBody string, responseHeaders map[string][]string, statusCode *int) *wafMatch {
	match := &wafMatch{fingerprint: &rule.fingerprint}

	for _, header := range rule.headers {
		if header.needsStatusCodeConfirmation && !isBlockedStatusCode(statusCode) {
			continue
		}
		values, exists := responseHeaders[header.name]
		if !exists || !containsHeaderValue(values, header.values) {
			continue
		}
		match.matchedHeaders = append(match.matchedHeaders, header.name)
		confidence := header.confidence
		if confidence == 0 {
			confidence = headerConfidence
		}
		if match.confidence < confidence {
			match.confidence = confidence
		}
	}

	for _, body := range rule.fingerprint.Body {
		if body.NegativeMatch || (body.NeedsStatusCodeConfirmation && !isBlockedStatusCode(statusCode)) {
			continue
		}
		if strings.Contains(responseBody, strings.ToLower(body.Pattern)) {
			match.matchedBodyPatterns = append(match.matchedBodyPatterns, body.Pattern)
			if match.confidence < bodyConfidence {
				match.confidence = bodyConfidence
			}
		}
	}

	if match.confidence == 0 {
		return nil
	}
	return match
}

func normalizeHeaders(headers map[string][]string) map[string][]string {
	processedHeaders := make(map[string][]string, len(headers))
	for name, values := range headers {
		normalizedName := strings.ToLower(strings.TrimSpace(name))
		for _, value := range values {
			processedHeaders[normalizedName] = append(processedHeaders[normalizedName], strings.ToLower(strings.TrimSpace(value)))
		}
	}
	return processedHeaders
}

func containsHeaderValue(actualValues, expectedValues []string) bool {
	if len(actualValues) == 0 {
		return false
	}
	if len(expectedValues) == 0 {
		for _, actual := range actualValues {
			if actual != "" {
				return true
			}
		}
		return false
	}
	for _, actual := range actualValues {
		for _, expected := range expectedValues {
			if actual == expected {
				return true
			}
		}
	}
	return false
}

func PopulateWafDetection(httpRequestResponse *wafcommon.HttpRequestResponse) {
	if httpRequestResponse == nil || httpRequestResponse.Response == nil {
		return
	}

	response := httpRequestResponse.Response
	var responseBody *string
	if response.ResponseBody != nil {
		responseBody = requesthelpers.GetResponseBodyStringFromBodyStruct(response.ResponseBody)
	}

	match := fingerprintApplicationFirewall(responseBody, response.ResponseHeaders, response.StatusCode)
	if match == nil {
		response.WafDetection = nil
		return
	}

	response.WafDetection = &wafcommon.WafDetection{
		Provider:                  match.fingerprint.Provider,
		Fingerprint:               match.fingerprint,
		MatchedHeaders:            match.matchedHeaders,
		MatchedServerHeaderValues: match.matchedServerHeaderValues,
		MatchedBodyPatterns:       match.matchedBodyPatterns,
	}
}
