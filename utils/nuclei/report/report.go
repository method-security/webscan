package nuclei

import (
	// Generated
	pentestgeneralfern "github.com/Method-Security/webscan/generated/go/pentest/general"
	// External
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// PopulateProbes loads all templates from the Nuclei engine and populates the probe information.
// It extracts payloads and expected matchers from each template.
func (b *Builder) PopulateProbes(eng *nuclei.NucleiEngine) error {
	if err := eng.LoadAllTemplates(); err != nil {
		return err
	}
	for _, template := range eng.GetTemplates() {
		id := template.ID
		if _, ok := b.probeIdx[id]; ok {
			continue
		}
		probe := &pentestgeneralfern.Probe{
			Id:               id,
			Payloads:         []string{},
			ExpectedMatchers: []*pentestgeneralfern.ExpectedMatcher{},
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
				vals := append(matcher.Words, matcher.Regex...)
				probe.ExpectedMatchers = append(probe.ExpectedMatchers, &pentestgeneralfern.ExpectedMatcher{
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
		probe = &pentestgeneralfern.Probe{Id: ev.TemplateID}
		b.probeIdx[ev.TemplateID] = probe
		b.report.Probes = append(b.report.Probes, probe)
	}

	// Get or create target
	host := hostKey(ev)
	targetInfo, ok := b.targetIdx[host]
	if !ok {
		targetInfo = &pentestgeneralfern.TargetInfo{Target: host}
		b.targetIdx[host] = targetInfo
		b.report.Targets = append(b.report.Targets, targetInfo)
	}

	// Build attempt information
	httpReqResp, _ := getHTTPRequestResponse(ev)
	attemptInfo := &pentestgeneralfern.AttemptInfo{
		ProbeId:             probe.Id,
		HttpRequestResponse: httpReqResp,
	}

	severity := ev.Info.SeverityHolder.Severity.String()
	attemptInfo.Finding = &pentestgeneralfern.FindingInfo{
		Name:     &ev.MatcherName,
		Finding:  ev.MatcherStatus,
		Severity: &severity,
		Tags:     ev.Info.Tags.ToSlice(),
	}

	// Always add the attempt to the report, even if there was an error parsing the request/response
	targetInfo.Attempts = append(targetInfo.Attempts, attemptInfo)
	targetInfo.RequestCount++
}

// Final returns the fully-populated Fern report.
// It should be called after all ResultEvents have been consumed.
func (b *Builder) Final() *pentestgeneralfern.PentestGeneralReport {
	return b.report
}
