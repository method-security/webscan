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
// SEC-702.A: attemptIdx merges Nuclei events by (target, templateId).
// Nuclei emits one ResultEvent per matched extractor/matcher; without
// the merge, the same template firing two extractors on the same host
// produced two AttemptInfo entries downstream. Engines de-duped by
// templateId and silently dropped the second event's extractor data
// (e.g. device_serial captured by extractor B was lost because
// extractor A's event arrived first). With the merge, the engine sees
// a single consolidated AttemptInfo per (target, templateId) carrying
// the union of all extractor outputs in ExtractedFields.
type Builder struct {
	mu         sync.Mutex
	targets    []*nuclei.NucleiTargetInfo
	probeIdx   map[string]*nuclei.NucleiProbe      // template-id → Probe
	targetIdx  map[string]*nuclei.NucleiTargetInfo // host/baseURL → TargetInfo
	attemptIdx map[string]map[string]*nuclei.NucleiAttemptInfo
}

// NewBuilder creates and returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{
		targets:    []*nuclei.NucleiTargetInfo{},
		probeIdx:   make(map[string]*nuclei.NucleiProbe),
		targetIdx:  make(map[string]*nuclei.NucleiTargetInfo),
		attemptIdx: make(map[string]map[string]*nuclei.NucleiAttemptInfo),
	}
}
