package nuclei

import (
	// Generated
	"fmt"
	"regexp"
	"strings"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// extractPayloadsFromRequest extracts payloads from a request and adds them to the probe
func (b *Builder) extractPayloadsFromRequest(probe *nuclei.NucleiProbe, payloads map[string]interface{}) {
	for _, raw := range payloads {
		switch v := raw.(type) {
		case []string:
			probe.Payloads = append(probe.Payloads, v...)
		case []interface{}:
			for _, iv := range v {
				if s, ok := iv.(string); ok {
					probe.Payloads = append(probe.Payloads, s)
				}
			}
		}
	}
}

// buildMatcherValues builds values array based on matcher type and extracted fields
func (b *Builder) buildMatcherValues(matcherType string, words []string, regex []string, status []int, size []int, dsl []string, binary []string) []string {
	var vals []string

	// Handle different matcher types using the original switch logic
	switch matcherType {
	case "word":
		vals = append(vals, words...)
	case "regex":
		vals = append(vals, regex...)
	case "status":
		for _, s := range status {
			vals = append(vals, fmt.Sprintf("%d", s))
		}
	case "size":
		for _, s := range size {
			vals = append(vals, fmt.Sprintf("%d", s))
		}
	case "dsl":
		vals = append(vals, dsl...)
	case "binary":
		vals = append(vals, binary...)
	default:
		// Fallback for unknown types - try to extract from common fields
		vals = append(vals, words...)
		vals = append(vals, regex...)
	}

	return vals
}

// addOrMergeCWE adds a CWE to the slice if it doesn't exist by ID
func addOrMergeCWE(cwes *[]*nuclei.CweDetails, cweID string) {
	// Check if CWE with this ID already exists
	for _, existing := range *cwes {
		if existing.Id == cweID {
			// CWE already exists, no need to add again
			return
		}
	}

	// CWE doesn't exist, add it
	*cwes = append(*cwes, &nuclei.CweDetails{
		Id: cweID,
	})
}

// addOrMergeCVE adds a CVE to the slice if it doesn't exist by ID, or merges additional fields if it does
func addOrMergeCVE(cves *[]*nuclei.CveDetails, cveID string, cvssMetrics *string, cvssScore *float64, epssScore *float64, epssPercentile *float64, cpe *string) {
	// Check if CVE with this ID already exists
	for _, existing := range *cves {
		if existing.Id == cveID {
			// Merge additional fields if they're not already set
			if existing.CvssMetrics == nil && cvssMetrics != nil {
				existing.CvssMetrics = cvssMetrics
			}
			if existing.CvssScore == nil && cvssScore != nil {
				existing.CvssScore = cvssScore
			}
			if existing.EpssScore == nil && epssScore != nil {
				existing.EpssScore = epssScore
			}
			if existing.EpssPercentile == nil && epssPercentile != nil {
				existing.EpssPercentile = epssPercentile
			}
			if existing.Cpe == nil && cpe != nil {
				existing.Cpe = cpe
			}
			return
		}
	}

	// CVE doesn't exist, add it with all available fields
	*cves = append(*cves, &nuclei.CveDetails{
		Id:             cveID,
		CvssMetrics:    cvssMetrics,
		CvssScore:      cvssScore,
		EpssScore:      epssScore,
		EpssPercentile: epssPercentile,
		Cpe:            cpe,
	})
}

// PopulateProbes loads all templates from the Nuclei engine and populates the probe information.
// It extracts payloads and expected matchers from each template.
func (b *Builder) PopulateProbes(eng *nucleilib.NucleiEngine) error {
	if err := eng.LoadAllTemplates(); err != nil {
		return err
	}
	for _, template := range eng.GetTemplates() {
		id := template.ID
		if _, ok := b.probeIdx[id]; ok {
			continue
		}
		probe := &nuclei.NucleiProbe{
			Payloads:       []string{},
			MatcherDetails: &nuclei.NucleiMatcherDetails{},
		}

		// Check if RequestsHTTP is available, otherwise use RequestsHeadless
		if len(template.RequestsHTTP) > 0 {
			for _, request := range template.RequestsHTTP {
				// Extract payloads
				b.extractPayloadsFromRequest(probe, request.Payloads)
				// Extract expected matchers
				var matchers []*nuclei.NucleiExpectedMatcher

				for _, matcher := range request.Matchers {
					vals := b.buildMatcherValues(
						matcher.Type.String(),
						matcher.Words,
						matcher.Regex,
						matcher.Status,
						matcher.Size,
						matcher.DSL,
						matcher.Binary,
					)

					expectedMatcher := &nuclei.NucleiExpectedMatcher{
						Type:   matcher.Type.String(),
						Part:   &matcher.Part,
						Values: vals,
					}

					matchers = append(matchers, expectedMatcher)
				}

				// Only add if there are actual matchers to avoid empty entries
				if len(matchers) > 0 {
					// Use the request-level MatchersCondition, not individual matcher conditions
					condition := request.MatchersCondition
					if condition == "" {
						condition = "OR" // Default condition
					}

					probe.MatcherDetails = &nuclei.NucleiMatcherDetails{
						MatcherCondition: nuclei.NucleiMatcherConditionEnum(strings.ToUpper(condition)),
						Matchers:         matchers,
					}
				}
			}
		} else if len(template.RequestsHeadless) > 0 {
			for _, request := range template.RequestsHeadless {
				// Extract payloads
				b.extractPayloadsFromRequest(probe, request.Payloads)
				// Extract expected matchers
				var matchers []*nuclei.NucleiExpectedMatcher

				for _, matcher := range request.Matchers {
					vals := b.buildMatcherValues(
						matcher.Type.String(),
						matcher.Words,
						matcher.Regex,
						matcher.Status,
						matcher.Size,
						matcher.DSL,
						matcher.Binary,
					)

					expectedMatcher := &nuclei.NucleiExpectedMatcher{
						Type:   matcher.Type.String(),
						Part:   &matcher.Part,
						Values: vals,
					}

					matchers = append(matchers, expectedMatcher)
				}

				// Only add if there are actual matchers to avoid empty entries
				if len(matchers) > 0 {
					// Use the request-level MatchersCondition, not individual matcher conditions
					condition := request.MatchersCondition
					if condition == "" {
						condition = "OR" // Default condition
					}

					probe.MatcherDetails = &nuclei.NucleiMatcherDetails{
						MatcherCondition: nuclei.NucleiMatcherConditionEnum(strings.ToUpper(condition)),
						Matchers:         matchers,
					}
				}
			}
		}
		b.probeIdx[id] = probe
	}
	return nil
}

// Consume processes a single Nuclei result event and updates the report accordingly.
// It handles probe information, target bucketing, and attempt tracking.
func (b *Builder) Consume(ev *nout.ResultEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Get or create probe
	probe, ok := b.probeIdx[ev.TemplateID]
	if !ok {
		probe = &nuclei.NucleiProbe{}
		b.probeIdx[ev.TemplateID] = probe
	}

	// Get or create target
	baseURL := getBaseURL(ev)
	targetInfo, ok := b.targetIdx[baseURL]
	if !ok {
		targetInfo = &nuclei.NucleiTargetInfo{Target: baseURL}
		b.targetIdx[baseURL] = targetInfo
		b.targets = append(b.targets, targetInfo)
	}

	// Build request-response for this event
	httpReqResp, _ := getHTTPRequestResponse(ev)

	// Create unique key for template+target combination
	requestKey := ev.TemplateID + ":" + baseURL

	// Always collect this request for potential multi-request templates
	b.pendingRequests[requestKey] = append(b.pendingRequests[requestKey], httpReqResp)

	// Only create an attempt if this is a positive match
	if !ev.MatcherStatus {
		return
	}

	// This is a positive match - collect all requests for this template+target
	allRequests := b.pendingRequests[requestKey]

	// Extract all HTTP requests from the metadata if available
	// This contains all the HTTP requests from the template execution
	var allHTTPRequestResponses []*common.HttpRequestResponse
	if ev.Metadata != nil {
		if allReqs, ok := ev.Metadata["all_http_requests"].([]map[string]string); ok && len(allReqs) > 0 {
			// Convert from Nuclei format to our common format
			for _, req := range allReqs {
				// Parse the request and response to create our HttpRequestResponse
				parsedReq := b.parseNucleiHTTPRequest(req, baseURL)
				if parsedReq != nil {
					allHTTPRequestResponses = append(allHTTPRequestResponses, parsedReq)
				}
			}
		} else {
			// Fallback to the single request we collected
			allHTTPRequestResponses = allRequests
		}
	} else {
		// Fallback to the single request we collected
		allHTTPRequestResponses = allRequests
	}

	// Filter out the matching request from the supporting requests
	var supportingRequests []*common.HttpRequestResponse
	for _, req := range allHTTPRequestResponses {
		// Compare request details to see if this is the matching request
		if !b.isSameRequest(req, httpReqResp) {
			supportingRequests = append(supportingRequests, req)
		}
	}

	// Build attempt information
	attemptInfo := &nuclei.NucleiAttemptInfo{
		TemplateId:                     ev.TemplateID,
		HttpRequestResponse:            httpReqResp,        // The matching request
		SupportingHttpRequestResponses: supportingRequests, // All other requests from template execution
	}

	// Extract vulnerability details from template if present
	var classificationDetails *nuclei.ClassificationDetails
	var cwes []*nuclei.CweDetails
	var cves []*nuclei.CveDetails

	// Use regex to match CVE template IDs (e.g., CVE-2001-0537)
	cveRegex := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	if cveRegex.MatchString(ev.TemplateID) {
		addOrMergeCVE(&cves, ev.TemplateID, nil, nil, nil, nil, nil)
	}
	// Pull out CWE and CVE IDs from the template classification
	if ev.Info.Classification != nil {
		for _, cweID := range ev.Info.Classification.CWEID.ToSlice() {
			addOrMergeCWE(&cwes, cweID)
		}

		// Extract CVE fields from classification if available
		var cvssMetrics *string
		var cvssScore *float64
		var epssScore *float64
		var epssPercentile *float64
		var cpe *string
		if ev.Info.Classification.CVSSMetrics != "" {
			cvssMetrics = &ev.Info.Classification.CVSSMetrics
		}
		if ev.Info.Classification.CVSSScore != 0 {
			cvssScore = &ev.Info.Classification.CVSSScore
		}
		if ev.Info.Classification.EPSSScore != 0 {
			epssScore = &ev.Info.Classification.EPSSScore
		}
		if ev.Info.Classification.EPSSPercentile != 0 {
			epssPercentile = &ev.Info.Classification.EPSSPercentile
		}
		if ev.Info.Classification.CPE != "" {
			cpe = &ev.Info.Classification.CPE
		}
		for _, cveID := range ev.Info.Classification.CVEID.ToSlice() {
			addOrMergeCVE(&cves, cveID, cvssMetrics, cvssScore, epssScore, epssPercentile, cpe)
		}
	}
	classificationDetails = &nuclei.ClassificationDetails{
		Cwes: cwes,
		Cves: cves,
	}
	severity := ev.Info.SeverityHolder.Severity.String()

	// Extract finding-level fields
	var name *string
	var description *string
	var impact *string
	var remediation *string
	var reference []string

	if ev.Info.Name != "" {
		name = &ev.Info.Name
	}
	if ev.Info.Description != "" {
		description = &ev.Info.Description
	}
	if ev.Info.Impact != "" {
		impact = &ev.Info.Impact
	}
	if ev.Info.Remediation != "" {
		remediation = &ev.Info.Remediation
	}
	if ev.Info.Reference != nil {
		reference = ev.Info.Reference.ToSlice()
	}
	var softwareWeakness string
	if ev.Info.Metadata["method-software-weakness-name"] != nil {
		softwareWeakness = ev.Info.Metadata["method-software-weakness-name"].(string)
	}

	attemptInfo.Finding = &nuclei.NucleiFindingInfo{
		Name:             name,
		SoftwareWeakness: &softwareWeakness,
		Description:      description,
		Impact:           impact,
		Remediation:      remediation,
		Reference:        reference,
		Classification:   classificationDetails,
		Severity:         &severity,
		Finding:          ev.MatcherStatus,
		Probe:            probe,
	}

	// Always add the attempt to the report, even if there was an error parsing the request/response
	targetInfo.Attempts = append(targetInfo.Attempts, attemptInfo)

	// Clean up pending requests for this template+target since we've processed them
	delete(b.pendingRequests, requestKey)
}

// parseNucleiHTTPRequest converts a Nuclei HttpRequestResponse to our common format
func (b *Builder) parseNucleiHTTPRequest(nucleiReq map[string]string, baseURL string) *common.HttpRequestResponse {
	// Parse the raw request string to extract components
	method, path, headers, body := parseRawRequest(nucleiReq["request"])

	// Create the request object
	request := common.HttpRequest{
		BaseUrl:     baseURL,
		Path:        path,
		Params:      &common.HttpRequestParams{},
		BaseHeaders: singleToMulti(headers),
		SentAt:      time.Now(), // We don't have the exact time, use current
	}

	// Set the HTTP method
	if m, err := common.NewHttpMethodFromString(strings.ToUpper(method)); err == nil {
		request.Method = m
	}

	// Parse body if present
	if body != "" {
		contentType := "application/x-www-form-urlencoded" // Default
		if ct, ok := headers["Content-Type"]; ok {
			contentType = ct
		}
		request.Params.Body = requesthelpers.CreateBodyFromBytes(contentType, []byte(body))
	}

	// Parse the raw response string to extract components
	statusCode, responseHeaders, responseBody := parseRawResponse(nucleiReq["response"])

	// Create the response object using the helper function
	response := requesthelpers.CreateHTTPResponse(statusCode, nil, singleToMulti(responseHeaders), responseBody)

	return &common.HttpRequestResponse{
		Request:  &request,
		Response: &response,
	}
}

// isSameRequest compares two HTTP request-response pairs to see if they're the same
func (b *Builder) isSameRequest(req1, req2 *common.HttpRequestResponse) bool {
	if req1 == nil || req2 == nil {
		return false
	}
	if req1.Request == nil || req2.Request == nil {
		return false
	}
	if req1.Response == nil || req2.Response == nil {
		return false
	}

	// Compare request path and method
	if req1.Request.Path != req2.Request.Path {
		return false
	}
	if req1.Request.Method != req2.Request.Method {
		return false
	}

	// Compare response status code
	if req1.Response.StatusCode == nil || req2.Response.StatusCode == nil {
		return req1.Response.StatusCode == req2.Response.StatusCode
	}
	if *req1.Response.StatusCode != *req2.Response.StatusCode {
		return false
	}

	return true
}

// Final returns the fully-populated Fern report.
// It should be called after all ResultEvents have been consumed.
func (b *Builder) Final() []*nuclei.NucleiTargetInfo {
	return b.targets
}
