package discoverroute

import (
	"strings"

	"github.com/Method-Security/webscan/generated/go/discover"
)

// InterpolatedUnrootedEvidence marks an interpolated route whose base could not be resolved inside
// the bundle. It is an intermediate state: ResolveUnrootedInterpolatedRoutes either roots the route
// against corroborating evidence or drops it, so it never reaches the report.
const InterpolatedUnrootedEvidence = "interpolated-unrooted"

// UnrootedEvidenceFor tags a candidate with the base it was built from, so candidates sharing a base
// can share whatever prefix corroboration establishes for it.
func UnrootedEvidenceFor(baseName string) string {
	if baseName == "" {
		return InterpolatedUnrootedEvidence
	}
	return InterpolatedUnrootedEvidence + ":" + baseName
}

// IsUnrootedEvidence reports a candidate awaiting rooting.
func IsUnrootedEvidence(evidence *string) bool {
	return evidence != nil && strings.HasPrefix(*evidence, InterpolatedUnrootedEvidence)
}

// unrootedBaseName returns the base recorded on a candidate, or "" when it carried none.
func unrootedBaseName(evidence *string) string {
	if !IsUnrootedEvidence(evidence) {
		return ""
	}
	_, name, found := strings.Cut(*evidence, ":")
	if !found {
		return ""
	}
	return name
}

// corroboratingEvidence reports whether a route is evidence the server actually serves that path.
//
// Only observed routes qualify. A route-table declaration is a client-side route, so an SPA serving
// /products while its API lives at /api/v2/products would otherwise confirm the wrong prefix — the
// same failure this resolution exists to prevent. Strings lifted from a bundle are ambiguous for the
// same reason, and an interpolated route must never corroborate itself or another candidate.
func corroboratingEvidence(route *discover.RouteDetails) bool {
	return route.Evidence == nil
}

// anchorSegment returns the first literal segment of a path, which is what a candidate is matched on.
func anchorSegment(path string) (string, bool) {
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || strings.Contains(segment, "{") {
			continue
		}
		return segment, true
	}
	return "", false
}

// ResolveUnrootedInterpolatedRoutes roots interpolated candidates whose base was unresolvable, using
// the paths the application is already known to serve.
//
// A candidate carries the path that followed the interpolated base, so `${base}/basket/{id}` arrives
// as `/basket/{id}`. Whether that is the real path depends entirely on what the base held, which the
// bundle may never state. Corroborating against observed routes answers it without assuming: if the
// application serves paths under `/basket` the candidate is already rooted, and if it instead serves
// `/api/v2/basket` the candidate is missing that prefix.
func ResolveUnrootedInterpolatedRoutes(routes []*discover.RouteDetails) []*discover.RouteDetails {
	type originAnchor struct {
		origin string
		anchor string
	}
	anchorsAtRoot := map[originAnchor]struct{}{}
	prefixesByAnchor := map[originAnchor]map[string]struct{}{}

	for _, route := range routes {
		if !corroboratingEvidence(route) {
			continue
		}
		origin := NormalizeBaseURLForIdentity(route.BaseUrl)
		segments := strings.Split(route.Path, "/")
		for i, segment := range segments {
			if i == 0 || segment == "" || strings.Contains(segment, "{") {
				continue
			}
			key := originAnchor{origin: origin, anchor: segment}
			if i == 1 {
				anchorsAtRoot[key] = struct{}{}
				continue
			}
			if prefixesByAnchor[key] == nil {
				prefixesByAnchor[key] = map[string]struct{}{}
			}
			prefixesByAnchor[key][strings.Join(segments[:i], "/")] = struct{}{}
		}
	}

	// First pass: root every candidate its own anchor corroborates, recording what each base implied.
	type originBase struct {
		origin string
		base   string
	}
	prefixByBase := map[originBase]map[string]struct{}{}
	prefixes := make(map[*discover.RouteDetails]string, len(routes))
	for _, route := range routes {
		if !IsUnrootedEvidence(route.Evidence) {
			continue
		}
		anchor, ok := anchorSegment(route.Path)
		if !ok {
			continue
		}
		key := originAnchor{origin: NormalizeBaseURLForIdentity(route.BaseUrl), anchor: anchor}
		prefix, ok := corroboratedPrefix(key, anchorsAtRoot, prefixesByAnchor)
		if !ok {
			continue
		}
		prefixes[route] = prefix
		base := unrootedBaseName(route.Evidence)
		if base == "" {
			continue
		}
		baseKey := originBase{origin: key.origin, base: base}
		if prefixByBase[baseKey] == nil {
			prefixByBase[baseKey] = map[string]struct{}{}
		}
		prefixByBase[baseKey][prefix] = struct{}{}
	}

	resolved := make([]*discover.RouteDetails, 0, len(routes))
	for _, route := range routes {
		if !IsUnrootedEvidence(route.Evidence) {
			resolved = append(resolved, route)
			continue
		}

		prefix, rooted := prefixes[route]
		if !rooted {
			// Second pass: inherit the prefix corroboration established for the same base, but only
			// when every corroborated candidate for that base agreed on it.
			agreed, ok := prefixByBase[originBase{
				origin: NormalizeBaseURLForIdentity(route.BaseUrl),
				base:   unrootedBaseName(route.Evidence),
			}]
			if !ok || len(agreed) != 1 {
				continue
			}
			for only := range agreed {
				prefix = only
			}
		}

		rootedPath, params := RenumberPositionalParams(prefix+route.Path, route.PathParams)
		evidence := InterpolatedRouteEvidence
		route.Path = rootedPath
		route.PathParams = params
		route.PathTemplate = &rootedPath
		route.Evidence = &evidence
		resolved = append(resolved, route)
	}

	return resolved
}

// corroboratedPrefix returns the prefix the application demonstrably serves this anchor under.
func corroboratedPrefix[K comparable](
	key K,
	anchorsAtRoot map[K]struct{},
	prefixesByAnchor map[K]map[string]struct{},
) (string, bool) {
	if _, rooted := anchorsAtRoot[key]; rooted {
		return "", true
	}
	candidates := prefixesByAnchor[key]
	// More than one prefix serves this anchor, so which one applies is unknown.
	if len(candidates) != 1 {
		return "", false
	}
	for candidate := range candidates {
		return candidate, true
	}
	return "", false
}
