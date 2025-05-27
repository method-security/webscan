package nuclei

import (
	// Standard
	"sync"
	// Generated
	pentestgeneralfern "github.com/Method-Security/webscan/generated/go/pentest/general"
)

// Builder constructs and manages Nuclei scan reports.
// It maintains indexes for probes and targets to efficiently process scan results.
type Builder struct {
	mu        sync.Mutex
	report    *pentestgeneralfern.Report
	probeIdx  map[string]*pentestgeneralfern.Probe      // template-id → Probe
	targetIdx map[string]*pentestgeneralfern.TargetInfo // host/baseURL → TargetInfo
}

// NewBuilder creates and returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{
		report:    &pentestgeneralfern.Report{},
		probeIdx:  make(map[string]*pentestgeneralfern.Probe),
		targetIdx: make(map[string]*pentestgeneralfern.TargetInfo),
	}
}

// PopulateConfig sets the configuration for the report.
func (b *Builder) PopulateConfig(config pentestgeneralfern.Config) error {
	b.report.Config = &config
	return nil
}
