package discoverroute

import (
	"strings"
)

// DeclaredRouteEvidence marks a route the application itself declares, not one merely observed.
const DeclaredRouteEvidence = "route-table"

// EvidenceRank orders a declaration above an interpolation above where the content was found.
func EvidenceRank(evidence *string) int {
	if evidence == nil {
		return 0
	}
	switch {
	case *evidence == DeclaredRouteEvidence:
		return 3
	case *evidence == InterpolatedRouteEvidence:
		return 2
	default:
		return 1
	}
}

// IsProvenanceEvidence reports evidence recording how a route was derived, not where it was found.
func IsProvenanceEvidence(evidence string) bool {
	return EvidenceRank(&evidence) >= 2
}

// IsTemplatedPath reports a declaration rather than a URL that can be requested.
func IsTemplatedPath(path string) bool {
	return strings.Contains(path, "{") && strings.Contains(path, "}")
}

// InterpolatedRouteEvidence marks a route whose parameter is proven but only loosely named.
const InterpolatedRouteEvidence = "interpolated"
