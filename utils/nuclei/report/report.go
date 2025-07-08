package nuclei

import (
	// Generated

	"regexp"
	"slices"

	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	// External
	"fmt"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

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
			Id:               id,
			Payloads:         []string{},
			ExpectedMatchers: []*nuclei.NucleiExpectedMatcher{},
		}
		for _, request := range template.RequestsHTTP {
			// Extract payloads
			for _, raw := range request.Payloads {
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
			// Extract expected matchers
			for _, matcher := range request.Matchers {
				var vals []string

				// Handle different matcher types
				switch matcher.Type.String() {
				case "word":
					vals = append(vals, matcher.Words...)
				case "regex":
					vals = append(vals, matcher.Regex...)
				case "status":
					for _, status := range matcher.Status {
						vals = append(vals, fmt.Sprintf("%d", status))
					}
				case "size":
					for _, size := range matcher.Size {
						vals = append(vals, fmt.Sprintf("%d", size))
					}
				case "dsl":
					vals = append(vals, matcher.DSL...)
				case "binary":
					vals = append(vals, matcher.Binary...)
				default:
					// Fallback for unknown types - try to extract from common fields
					vals = append(vals, matcher.Words...)
					vals = append(vals, matcher.Regex...)
				}

				probe.ExpectedMatchers = append(probe.ExpectedMatchers, &nuclei.NucleiExpectedMatcher{
					Type:  matcher.Type.String(),
					Value: vals,
				})
			}
		}
		b.probeIdx[id] = probe
		b.report.Probes = append(b.report.Probes, probe)
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
		probe = &nuclei.NucleiProbe{Id: ev.TemplateID}
		b.probeIdx[ev.TemplateID] = probe
		b.report.Probes = append(b.report.Probes, probe)
	}

	// Get or create target
	host := hostKey(ev)
	targetInfo, ok := b.targetIdx[host]
	if !ok {
		targetInfo = &nuclei.NucleiTargetInfo{Target: host}
		b.targetIdx[host] = targetInfo
		b.report.Targets = append(b.report.Targets, targetInfo)
	}

	// Build attempt information
	httpReqResp, _ := getHTTPRequestResponse(ev)
	attemptInfo := &nuclei.NucleiAttemptInfo{
		ProbeId:             probe.Id,
		HttpRequestResponse: httpReqResp,
	}

	// Extract vulnerability details from template if present
	var classificationDetails *nuclei.ClassificationDetails
	var cweIds []string
	var cveIds []string

	// Use regex to match CVE template IDs (e.g., CVE-2001-0537)
	cveRegex := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	if cveRegex.MatchString(ev.TemplateID) {
		if !slices.Contains(cveIds, ev.TemplateID) {
			cveIds = append(cveIds, ev.TemplateID)
		}
	}
	// Pull out CWE and CVE IDs from the template classification
	if ev.Info.Classification != nil {
		for _, cweId := range ev.Info.Classification.CWEID.ToSlice() {
			if !slices.Contains(cweIds, cweId) {
				cweIds = append(cweIds, cweId)
			}
		}
		for _, cveId := range ev.Info.Classification.CVEID.ToSlice() {
			if !slices.Contains(cveIds, cveId) {
				cveIds = append(cveIds, cveId)
			}
		}
	}
	classificationDetails = &nuclei.ClassificationDetails{
		CweIds: cweIds,
		CveIds: cveIds,
	}
	severity := ev.Info.SeverityHolder.Severity.String()
	attemptInfo.Finding = &nuclei.NucleiFindingInfo{
		Name:           &ev.MatcherName,
		Finding:        ev.MatcherStatus,
		Severity:       &severity,
		Tags:           ev.Info.Tags.ToSlice(),
		Classification: classificationDetails,
	}

	// Always add the attempt to the report, even if there was an error parsing the request/response
	targetInfo.Attempts = append(targetInfo.Attempts, attemptInfo)
	targetInfo.RequestCount++
}

// Final returns the fully-populated Fern report.
// It should be called after all ResultEvents have been consumed.
func (b *Builder) Final() *nuclei.NucleiReport {
	return b.report
}
