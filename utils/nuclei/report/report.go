package nuclei

import (
	// Standard
	"fmt"
	"regexp"
	"strings"

	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
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

		// Record the declaration-order named extractors per template
		// so Consume can recover names from matcher-emitted events
		// whose ExtractorName Nuclei dropped.
		var extractorNames []string

		// Check if RequestsHTTP is available, otherwise use RequestsHeadless
		if len(template.RequestsHTTP) > 0 {
			for _, request := range template.RequestsHTTP {
				// Extract payloads
				b.extractPayloadsFromRequest(probe, request.Payloads)
				for _, extractor := range request.Extractors {
					if extractor.Name != "" {
						extractorNames = append(extractorNames, extractor.Name)
					}
				}
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
				for _, extractor := range request.Extractors {
					if extractor.Name != "" {
						extractorNames = append(extractorNames, extractor.Name)
					}
				}
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
		if len(extractorNames) > 0 {
			b.extractorNamesIdx[id] = extractorNames
		}
	}
	return nil
}

// Consume processes a single Nuclei result event and updates the report accordingly.
// It handles probe information, target bucketing, and attempt tracking.
//
// Events sharing a (target, templateId) pair are merged into one
// AttemptInfo. The first event populates the Finding; subsequent
// events overlay their ExtractedFields onto the same AttemptInfo so
// downstream engines see a single consolidated record per template per
// target. Non-extractor fields (Metadata, classification, severity,
// HTTP request/response) are template-stable, so the first-event copy
// is authoritative.
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
	targetURL := getTargetURL(ev)
	targetInfo, ok := b.targetIdx[targetURL]
	if !ok {
		targetInfo = &nuclei.NucleiTargetInfo{Target: targetURL}
		b.targetIdx[targetURL] = targetInfo
		b.targets = append(b.targets, targetInfo)
	}

	// Check the (target, templateId) merge index first. If we've
	// already built an AttemptInfo for this pair, the only per-event
	// field that varies is ExtractorName/ExtractedResults; overlay
	// those into the existing Finding's ExtractedFields and skip the
	// rest of this function.
	templateAttempts, hasTargetTemplates := b.attemptIdx[targetURL]
	if !hasTargetTemplates {
		templateAttempts = make(map[string]*nuclei.NucleiAttemptInfo)
		b.attemptIdx[targetURL] = templateAttempts
	}
	if existing, alreadySeen := templateAttempts[ev.TemplateID]; alreadySeen {
		b.mergeExtractedFields(existing, ev)
		return
	}

	// Build attempt information
	httpReqResp, _ := getHTTPRequestResponse(ev)
	attemptInfo := &nuclei.NucleiAttemptInfo{
		TemplateId:          ev.TemplateID,
		HttpRequestResponse: httpReqResp,
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
	if v, ok := ev.Info.Metadata["method-software-weakness-name"].(string); ok {
		softwareWeakness = v
	}

	// Extract template metadata if available
	var metadata map[string]string
	if ev.Info.Metadata != nil {
		metadata = make(map[string]string)
		for key, value := range ev.Info.Metadata {
			if strValue, ok := value.(string); ok {
				metadata[key] = strValue
			}
		}
	}

	// Seed the per-host extractor map from this first event. Nuclei
	// emits ExtractorName only in the extractor-only branch of
	// MakeDefaultResultEvent; matcher-named events drop the name.
	// b.extractedFieldsFromEvent recovers the name from the template
	// definition when the upstream API doesn't carry it. nil is
	// returned when no extractor output is available.
	extractedFields := b.extractedFieldsFromEvent(ev)

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
		Metadata:         metadata,
		ExtractedFields:  extractedFields,
	}

	// Always add the attempt to the report, even if there was an error parsing the request/response
	targetInfo.Attempts = append(targetInfo.Attempts, attemptInfo)
	templateAttempts[ev.TemplateID] = attemptInfo
}

// mergeExtractedFields overlays the extractor outputs carried by ev
// onto an already-tracked AttemptInfo. Called by Consume when a
// second event arrives for the same (target, templateId) — typical
// when one template fires multiple matchers or multiple extractors
// on one host. First-write wins per extractor name (Nuclei rarely
// emits the same extractor twice on a single template run, but if
// it does we keep the earlier value to mirror Builder's "first event
// populates Finding" rule).
func (b *Builder) mergeExtractedFields(existing *nuclei.NucleiAttemptInfo, ev *nout.ResultEvent) {
	if existing == nil || existing.Finding == nil {
		return
	}
	fields := b.extractedFieldsFromEvent(ev)
	if len(fields) == 0 {
		return
	}
	if existing.Finding.ExtractedFields == nil {
		existing.Finding.ExtractedFields = make(map[string]string, len(fields))
	}
	for k, v := range fields {
		if _, present := existing.Finding.ExtractedFields[k]; present {
			continue
		}
		existing.Finding.ExtractedFields[k] = v
	}
}

// extractedFieldsFromEvent returns the per-extractor name → value
// map for one Nuclei result event. Two cases:
//
//  1. ev.ExtractorName non-empty — extractor-only branch of
//     MakeDefaultResultEvent. Single key/value, name preserved.
//
//  2. ev.ExtractorName empty AND ExtractedResults non-empty AND the
//     template has exactly one named extractor across ALL its
//     requests — matcher-named branch on a single-extractor
//     template. Join all flat results under that extractor's name.
//
// Multi-extractor templates do NOT get recovered. Nuclei's public
// SDK drops both the per-extractor name AND any per-request marker
// on matcher-emitted events, so we can't tell which extractor (or
// which request, for multi-request templates) produced which slice
// of ExtractedResults. Positional mapping would mis-attribute when
// (a) requests fire in a different order than declared, (b) Nuclei
// dedupes / reorders OutputExtracts across requests, or (c) only
// some extractors matched and the cardinality is incidentally
// matched. Authors who need multiple per-host fields on the same
// host should split into one template per field, each with a single
// named extractor; the (target, templateId) merge below collapses
// the wider Fingerprint into one AttemptInfo (per template) without
// requiring multi-extractor-per-template recovery.
//
// Engines downstream prefer a miss over a mis-attribution — never
// guess when the extractor-name mapping is ambiguous.
func (b *Builder) extractedFieldsFromEvent(ev *nout.ResultEvent) map[string]string {
	if ev.ExtractorName != "" {
		return map[string]string{
			ev.ExtractorName: strings.Join(ev.ExtractedResults, ","),
		}
	}
	if len(ev.ExtractedResults) == 0 {
		return nil
	}
	names := b.extractorNamesIdx[ev.TemplateID]
	if len(names) != 1 {
		// 0 declared (template has no named extractors) OR 2+ declared
		// (we'd have to guess which named the flat results belong to).
		// Drop — downstream engines miss rather than mis-attribute.
		return nil
	}
	return map[string]string{
		names[0]: strings.Join(ev.ExtractedResults, ","),
	}
}

// Final returns the fully-populated Fern report.
// It should be called after all ResultEvents have been consumed.
func (b *Builder) Final() []*nuclei.NucleiTargetInfo {
	return b.targets
}
