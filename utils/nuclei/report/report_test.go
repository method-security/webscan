package nuclei

import (
	"testing"

	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// SEC-702.A — Builder.extractedFieldsFromEvent name-recovery cases.
// Bugbot delta: Nuclei's MakeDefaultResultEvent drops ExtractorName
// on matcher-emitted events; we recover the name from the template
// definition stashed at PopulateProbes time.

func TestExtractedFieldsFromEvent_NamedExtractor(t *testing.T) {
	b := NewBuilder()
	ev := &nout.ResultEvent{
		TemplateID:       "mikrotik-version",
		ExtractorName:    "device_mac",
		ExtractedResults: []string{"00:1A:EF:67:31:34"},
	}
	got := b.extractedFieldsFromEvent(ev)
	if len(got) != 1 || got["device_mac"] != "00:1A:EF:67:31:34" {
		t.Fatalf("got %v; want {device_mac: 00:1A:EF:...}", got)
	}
}

func TestExtractedFieldsFromEvent_MatcherEventSingleNamedExtractor(t *testing.T) {
	// Common SEC-702 case: matcher AND extractor declared. Nuclei
	// emits a matcher-named event with empty ExtractorName but
	// flat ExtractedResults. We must recover the name from the
	// template definition.
	b := NewBuilder()
	b.extractorNamesIdx["dahua-cap-js"] = []string{"device_serial"}
	ev := &nout.ResultEvent{
		TemplateID:       "dahua-cap-js",
		ExtractorName:    "",
		ExtractedResults: []string{"3E023DBPAEMV65U"},
	}
	got := b.extractedFieldsFromEvent(ev)
	if got["device_serial"] != "3E023DBPAEMV65U" {
		t.Fatalf("got %v; want device_serial=3E023DBPAEMV65U", got)
	}
}

func TestExtractedFieldsFromEvent_MultiExtractorTemplateDropsAmbiguous(t *testing.T) {
	// Multi-extractor template: we have 2 declared named extractors
	// but no way to tell which produced which slice of the flat
	// results from a matcher event. Drop — engines miss rather than
	// mis-attribute. Authors needing multiple per-host fields should
	// split into separate single-extractor templates.
	b := NewBuilder()
	b.extractorNamesIdx["ubiquiti-airos"] = []string{"device_mac", "architecture_value"}
	ev := &nout.ResultEvent{
		TemplateID:       "ubiquiti-airos",
		ExtractedResults: []string{"00:1A:EF:67:31:34", "MIPSBE"},
	}
	if got := b.extractedFieldsFromEvent(ev); got != nil {
		t.Fatalf("got %v; want nil (multi-extractor template, can't disambiguate)", got)
	}
}

func TestExtractedFieldsFromEvent_MultiRequestTemplateConcatBugReproducer(t *testing.T) {
	// Bugbot Medium repro: a 2-request template with one named
	// extractor in each request ends up with extractorNamesIdx[id]
	// = ["a", "b"] after PopulateProbes (concatenated across
	// requests). When request 1 fires a matcher event with 1
	// extracted result, the count comparison sees 1 vs 2 and the
	// old "len(names) == len(results)" path would have skipped.
	// Under the conservative len(names)==1 rule it ALSO skips —
	// downstream misses rather than positionally mis-attributes
	// "request 1's value" to the wrong name.
	b := NewBuilder()
	b.extractorNamesIdx["multi-request"] = []string{"a", "b"} // concat across two requests
	ev := &nout.ResultEvent{
		TemplateID:       "multi-request",
		ExtractedResults: []string{"request_1_value"},
	}
	if got := b.extractedFieldsFromEvent(ev); got != nil {
		t.Fatalf("got %v; want nil (multi-extractor template, can't tell which request fired)", got)
	}
}

func TestExtractedFieldsFromEvent_NoTemplate(t *testing.T) {
	// Matcher event but no template definition recorded — drop.
	b := NewBuilder()
	ev := &nout.ResultEvent{
		TemplateID:       "unknown-template",
		ExtractedResults: []string{"value"},
	}
	if got := b.extractedFieldsFromEvent(ev); got != nil {
		t.Fatalf("got %v; want nil (template not registered)", got)
	}
}

func TestExtractedFieldsFromEvent_EmptyResults(t *testing.T) {
	b := NewBuilder()
	b.extractorNamesIdx["t"] = []string{"a"}
	ev := &nout.ResultEvent{TemplateID: "t"}
	if got := b.extractedFieldsFromEvent(ev); got != nil {
		t.Fatalf("got %v; want nil (no results)", got)
	}
}
