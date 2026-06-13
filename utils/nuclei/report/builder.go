package nuclei

import (
	// Standard
	"sync"
	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
)

// Builder constructs and manages Nuclei scan reports.
// It maintains indexes for probes and targets to efficiently process scan results.
//
// attemptIdx merges Nuclei events by (target, templateId). Nuclei
// emits one ResultEvent per matched extractor/matcher; without the
// merge, the same template firing two extractors on the same host
// produces two AttemptInfo entries downstream. Engines de-dup by
// templateId and silently drop the second event's extractor data
// (e.g. device_serial captured by extractor B is lost because
// extractor A's event arrived first). With the merge, the engine sees
// a single consolidated AttemptInfo per (target, templateId) carrying
// the union of all extractor outputs in ExtractedFields.
//
// extractorNamesIdx records the named extractors declared by each
// template. Nuclei's MakeDefaultResultEvent emits matcher-named
// ResultEvents WITHOUT ExtractorName whenever the template's matchers
// populate `Matches` (the typical matcher+extractor case); the event
// still carries flat `ExtractedResults` but the per-extractor names
// are dropped from the public SDK API. We recover the names
// positionally from the template definition when the cardinality
// matches — see Consume.
type Builder struct {
	mu                sync.Mutex
	targets           []*nuclei.NucleiTargetInfo
	probeIdx          map[string]*nuclei.NucleiProbe      // template-id → Probe
	targetIdx         map[string]*nuclei.NucleiTargetInfo // host/baseURL → TargetInfo
	attemptIdx        map[string]map[string]*nuclei.NucleiAttemptInfo
	extractorNamesIdx map[string][]string // template-id → declared extractor names (in declaration order, named only)
}

// NewBuilder creates and returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{
		targets:           []*nuclei.NucleiTargetInfo{},
		probeIdx:          make(map[string]*nuclei.NucleiProbe),
		targetIdx:         make(map[string]*nuclei.NucleiTargetInfo),
		attemptIdx:        make(map[string]map[string]*nuclei.NucleiAttemptInfo),
		extractorNamesIdx: make(map[string][]string),
	}
}
