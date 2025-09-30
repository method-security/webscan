package nuclei

import (
	// Standard
	"sync"
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
)

// Builder constructs and manages Nuclei scan reports.
// It maintains indexes for probes and targets to efficiently process scan results.
type Builder struct {
	mu        sync.Mutex
	targets   []*nuclei.NucleiTargetInfo
	probeIdx  map[string]*nuclei.NucleiProbe      // template-id → Probe
	targetIdx map[string]*nuclei.NucleiTargetInfo // host/baseURL → TargetInfo

	// Request collection for templates with multiple HTTP requests
	pendingRequests map[string][]*common.HttpRequestResponse // template-id:target → requests
}

// NewBuilder creates and returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{
		targets:         []*nuclei.NucleiTargetInfo{},
		probeIdx:        make(map[string]*nuclei.NucleiProbe),
		targetIdx:       make(map[string]*nuclei.NucleiTargetInfo),
		pendingRequests: make(map[string][]*common.HttpRequestResponse),
	}
}
