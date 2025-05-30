package nuclei

import (
	// Standard
	"sync"
	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
)

// Builder constructs and manages Nuclei scan reports.
// It maintains indexes for probes and targets to efficiently process scan results.
type Builder struct {
	mu        sync.Mutex
	report    *nuclei.NucleiReport
	probeIdx  map[string]*nuclei.NucleiProbe      // template-id → Probe
	targetIdx map[string]*nuclei.NucleiTargetInfo // host/baseURL → TargetInfo
}

// NewBuilder creates and returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{
		report:    &nuclei.NucleiReport{},
		probeIdx:  make(map[string]*nuclei.NucleiProbe),
		targetIdx: make(map[string]*nuclei.NucleiTargetInfo),
	}
}
