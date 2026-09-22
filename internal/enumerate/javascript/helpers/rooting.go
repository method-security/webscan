package enumeratejavascript

import (
	// Standard
	"net/url"
	"sort"
	"strings"

	// Generated
	"github.com/Method-Security/webscan/generated/go/enumerate"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

// RootEndpoints resolves relative endpoint literals against the API base the bundle configures.
//
// A bundle states its base once, as configuration, and then concatenates bare paths onto it. Left
// alone the two never meet: the literal `general/DeleteFile` is not a path the origin serves, and
// the base alone names no endpoint.
func RootEndpoints(endpoints []*enumerate.JavascriptEndpoint, baseCandidates []string, preferHost string) []*enumerate.JavascriptEndpoint {
	base, ok := preferredBase(baseCandidates, preferHost)
	if !ok {
		return endpoints
	}

	origin, prefix, err := splitBase(base)
	if err != nil {
		return endpoints
	}

	kept := make([]*enumerate.JavascriptEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		// The base itself names no endpoint, so it must not be reported as one.
		if endpoint.Rooted && endpoint.Path == prefix && endpoint.BaseUrl != nil && *endpoint.BaseUrl == origin {
			continue
		}
		if !endpoint.Rooted {
			endpoint.BaseUrl = &origin
			endpoint.Path = requesthelpers.JoinPath(prefix, endpoint.Path)
			endpoint.Rooted = true
		}
		kept = append(kept, endpoint)
	}
	return kept
}

// pageSuffixes mark a candidate as a page rather than an API base.
var pageSuffixes = []string{".aspx", ".asp", ".html", ".htm", ".php", ".jsp", ".do", ".cgi"}

// apiSegments name a path segment that marks a candidate as an API base.
var apiSegments = map[string]struct{}{
	"api": {}, "apis": {}, "rest": {}, "graphql": {}, "services": {}, "service": {},
	"v1": {}, "v2": {}, "v3": {}, "v4": {},
}

// preferredBase picks the API base from the absolute URLs a bundle references.
//
// A bundle references many absolute URLs, most of which are pages, CDNs or identity providers. The
// base is the one that reads as an API root: it carries a path, that path does not end in a page
// extension, and it names an API. Depth alone is not enough — a sign-out page sits deeper than
// `/serviceapi/v1` and would otherwise win.
func preferredBase(candidates []string, preferHost string) (string, bool) {
	ranked := append([]string{}, candidates...)
	sort.Strings(ranked)
	preferHost = strings.ToLower(preferHost)

	best := ""
	bestScore := 0
	for _, candidate := range ranked {
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Host == "" {
			continue
		}
		trimmed := strings.Trim(parsed.Path, "/")
		if trimmed == "" {
			continue
		}
		segments := strings.Split(trimmed, "/")
		if looksLikePage(segments[len(segments)-1]) {
			continue
		}

		score := 1
		for _, segment := range segments {
			lowered := strings.ToLower(segment)
			if _, exists := apiSegments[lowered]; exists {
				score += 10
				continue
			}
			if strings.HasSuffix(lowered, "api") || strings.HasSuffix(lowered, "apis") {
				score += 5
			}
		}
		if preferHost != "" && strings.EqualFold(parsed.Hostname(), preferHost) {
			score += 3
		}
		if score > bestScore {
			best = candidate
			bestScore = score
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// looksLikePage reports a final segment that names a document rather than an API root.
func looksLikePage(segment string) bool {
	lowered := strings.ToLower(segment)
	for _, suffix := range pageSuffixes {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	return false
}

// splitBase separates an API base into its origin and its path prefix.
func splitBase(base string) (string, string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", "", err
	}
	origin := parsed.Scheme + "://" + parsed.Host
	prefix := "/" + strings.Trim(parsed.Path, "/")
	if prefix == "/" {
		prefix = ""
	}
	return origin, prefix, nil
}

// BaseCandidatesInScope keeps only the origins that belong to the target host or a subdomain of it.
func BaseCandidatesInScope(candidates []string, targetURL string, ignoreCrossDomain bool) []string {
	if !ignoreCrossDomain {
		return candidates
	}

	target, err := url.Parse(targetURL)
	if err != nil || target.Host == "" {
		return candidates
	}
	targetHost := strings.ToLower(target.Hostname())

	kept := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		parsed, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == targetHost || strings.HasSuffix(host, "."+targetHost) {
			kept = append(kept, candidate)
		}
	}
	return kept
}
