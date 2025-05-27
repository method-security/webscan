package nuclei

import (
	// Generated
	nucleifern "github.com/Method-Security/webscan/generated/go/nuclei"
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
	for _, tpl := range eng.GetTemplates() {
		id := tpl.ID
		if _, ok := b.probeIdx[id]; ok {
			continue
		}
		pr := &nucleifern.Probe{
			Id:               id,
			Payloads:         []string{},
			ExpectedMatchers: []*nucleifern.ExpectedMatcher{},
		}
		for _, req := range tpl.RequestsHTTP {
			// Extract payloads
			for _, raw := range req.Payloads {
				switch v := raw.(type) {
				case []string:
					pr.Payloads = append(pr.Payloads, v...)
				case []interface{}:
					for _, iv := range v {
						if s, ok := iv.(string); ok {
							pr.Payloads = append(pr.Payloads, s)
						}
					}
				}
			}
			// Extract expected matchers
			for _, ma := range req.Matchers {
				vals := append(ma.Words, ma.Regex...)
				pr.ExpectedMatchers = append(pr.ExpectedMatchers, &nucleifern.ExpectedMatcher{
					Type:  ma.Type.String(),
					Value: vals,
				})
			}
		}
		b.probeIdx[id] = pr
		b.report.Probes = append(b.report.Probes, pr)
	}
	return nil
}

// Consume processes a single Nuclei result event and updates the report accordingly.
// It handles probe information, target bucketing, and attempt tracking.
func (b *Builder) Consume(ev *nout.ResultEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Get or create probe
	pr, ok := b.probeIdx[ev.TemplateID]
	if !ok {
		pr = &nucleifern.Probe{Id: ev.TemplateID}
		b.probeIdx[ev.TemplateID] = pr
		b.report.Probes = append(b.report.Probes, pr)
	}

	// Get or create target
	host := hostKey(ev)
	tg, ok := b.targetIdx[host]
	if !ok {
		tg = &nucleifern.TargetInfo{Target: host}
		b.targetIdx[host] = tg
		b.report.Targets = append(b.report.Targets, tg)
	}

	// Build attempt information
	reqResp, err := toReqResp(ev)
	if err != nil {
		// Handle error or log it
	}
	at := &nucleifern.AttemptInfo{
		ProbeId:             pr.Id,
		HttpRequestResponse: reqResp,
	}

	at.Finding = &nucleifern.FindingInfo{
		Name:     strPtr(ev.MatcherName),
		Finding:  ev.MatcherStatus,
		Severity: strPtr(ev.Info.SeverityHolder.Severity.String()),
		Tags:     ev.Info.Tags.ToSlice(),
	}

	tg.Attempts = append(tg.Attempts, at)
	tg.RequestCount++
}

// Final returns the fully-populated Fern report.
// It should be called after all ResultEvents have been consumed.
func (b *Builder) Final() *nucleifern.Report {
	return b.report
}
