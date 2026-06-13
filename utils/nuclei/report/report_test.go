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

func TestExtractedFieldsFromEvent_MatcherEventCardinalityMatch(t *testing.T) {
	// Multi-extractor template, positional cardinality match.
	b := NewBuilder()
	b.extractorNamesIdx["ubiquiti-airos"] = []string{"device_mac", "architecture_value"}
	ev := &nout.ResultEvent{
		TemplateID:       "ubiquiti-airos",
		ExtractedResults: []string{"00:1A:EF:67:31:34", "MIPSBE"},
	}
	got := b.extractedFieldsFromEvent(ev)
	if got["device_mac"] != "00:1A:EF:67:31:34" {
		t.Errorf("device_mac = %q; want 00:1A:EF:67:31:34", got["device_mac"])
	}
	if got["architecture_value"] != "MIPSBE" {
		t.Errorf("architecture_value = %q; want MIPSBE", got["architecture_value"])
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

func TestExtractedFieldsFromEvent_CardinalityMismatchSkips(t *testing.T) {
	// 3 declared extractors but only 2 runtime results — don't
	// guess; downstream prefers a miss over a mis-attribution.
	b := NewBuilder()
	b.extractorNamesIdx["multi-ext"] = []string{"a", "b", "c"}
	ev := &nout.ResultEvent{
		TemplateID:       "multi-ext",
		ExtractedResults: []string{"x", "y"},
	}
	if got := b.extractedFieldsFromEvent(ev); got != nil {
		t.Fatalf("got %v; want nil (3-extractor template with 2 results)", got)
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
