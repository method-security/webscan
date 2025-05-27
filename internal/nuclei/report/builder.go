package nuclei

import (
	// Standard
	"sync"
	// Generated
	nucleifern "github.com/Method-Security/webscan/generated/go/nuclei"
)

// Builder constructs and manages Nuclei scan reports.
// It maintains indexes for probes and targets to efficiently process scan results.
type Builder struct {
	mu        sync.Mutex
	report    *nucleifern.Report
	probeIdx  map[string]*nucleifern.Probe      // template-id → Probe
	targetIdx map[string]*nucleifern.TargetInfo // host/baseURL → TargetInfo
}

// NewBuilder creates and returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{
		report:    &nucleifern.Report{},
		probeIdx:  make(map[string]*nucleifern.Probe),
		targetIdx: make(map[string]*nucleifern.TargetInfo),
	}
}

// PopulateConfig sets the configuration for the report.
func (b *Builder) PopulateConfig(config nucleifern.Config) error {
	b.report.Config = &config
	return nil
}
