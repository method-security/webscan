package discoverroute

import (
	// Standard
	"strings"
	// Generated
	"github.com/Method-Security/webscan/generated/go/discover"
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

// MergePathParams merges two slices of RoutePathParam, retaining unique params and merging example values.
func MergePathParams(params1 []*discover.RoutePathParam, params2 []*discover.RoutePathParam) []*discover.RoutePathParam {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discover.RoutePathParam)
	order := make([]string, 0, len(params1)+len(params2))
	for _, param := range params1 {
		if _, exists := paramMap[param.Name]; !exists {
			order = append(order, param.Name)
		}
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		existingParam, exists := paramMap[param.Name]
		if !exists {
			paramMap[param.Name] = param
			order = append(order, param.Name)
			continue
		}
		if existingParam.ExampleValues != nil && param.ExampleValues != nil {
			// Use a set to deduplicate example values
			valueSet := make(map[string]struct{})
			for _, val := range existingParam.ExampleValues {
				valueSet[val] = struct{}{}
			}
			deduplicatedValues := existingParam.ExampleValues
			for _, val := range param.ExampleValues {
				if _, seen := valueSet[val]; seen {
					continue
				}
				valueSet[val] = struct{}{}
				deduplicatedValues = append(deduplicatedValues, val)
			}
			existingParam.ExampleValues = deduplicatedValues
		} else if param.ExampleValues != nil {
			existingParam.ExampleValues = param.ExampleValues
		} // else existingParam.ExampleValues is already set
		paramMap[param.Name] = existingParam
	}

	// Path parameters are positional, so preserve insertion order rather than ranging the map.
	mergedParams := make([]*discover.RoutePathParam, 0, len(order))
	for _, name := range order {
		mergedParams = append(mergedParams, paramMap[name])
	}
	return mergedParams
}

// InterpolatedRouteEvidence marks a route whose parameter is proven but only loosely named.
const InterpolatedRouteEvidence = "interpolated"
