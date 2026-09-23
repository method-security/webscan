package enumeratejavascript

import (
	// Standard
	"net/url"
	"sort"
	"strings"

	// Generated
	"github.com/Method-Security/webscan/generated/go/enumerate"
	// Utils
	utils "github.com/Method-Security/webscan/utils"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

// RootEndpoints resolves relative endpoint literals against the API base the bundle configures.
//
// A bundle states its base once, as configuration, and then concatenates bare paths onto it. Left
// alone the two never meet: the literal `general/DeleteFile` is not a path the origin serves, and
// the base alone names no endpoint.
func RootEndpoints(endpoints []*enumerate.JavascriptEndpoint, baseCandidates []string, preferHosts []string) []*enumerate.JavascriptEndpoint {
	base, ok := preferredBase(baseCandidates, preferHosts)
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
		// The base itself names no endpoint, so it must not be reported as one. `/x` and `/x/` are
		// the same base here even though they are different endpoints elsewhere.
		if endpoint.Rooted && endpoint.BaseUrl != nil && *endpoint.BaseUrl == origin &&
			strings.Trim(endpoint.Path, "/") == strings.Trim(prefix, "/") {
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
// base is the shallowest path that reads as an API root. Scoring depth upwards would let a full
// endpoint outrank the root it sits under, and relative literals would then be joined onto that
// longer path.
func preferredBase(candidates []string, preferHosts []string) (string, bool) {
	ranked := append([]string{}, candidates...)
	sort.Strings(ranked)

	preferred := map[string]struct{}{}
	for _, host := range preferHosts {
		preferred[strings.ToLower(host)] = struct{}{}
	}

	var best *scoredBase
	for _, candidate := range ranked {
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Host == "" {
			continue
		}
		trimmed := strings.Trim(parsed.EscapedPath(), "/")
		if trimmed == "" {
			continue
		}
		segments := strings.Split(trimmed, "/")
		last := segments[len(segments)-1]
		if looksLikePage(last) || utils.IsStaticAsset(parsed.EscapedPath()) {
			continue
		}

		_, sameHost := preferred[strings.ToLower(parsed.Hostname())]
		current := scoredBase{
			candidate: candidate,
			apiLike:   namesAnAPI(segments),
			sameHost:  sameHost,
			depth:     len(segments),
		}
		if best == nil || betterBase(current, *best) {
			chosen := current
			best = &chosen
		}
	}
	if best == nil {
		return "", false
	}
	return best.candidate, true
}

// scoredBase is a base candidate with the properties it is ranked on.
type scoredBase struct {
	candidate string
	apiLike   bool
	sameHost  bool
	depth     int
}

// betterBase ranks an API root above anything else, then a same-host base, then the shallower path.
func betterBase(current scoredBase, best scoredBase) bool {
	if current.apiLike != best.apiLike {
		return current.apiLike
	}
	if current.sameHost != best.sameHost {
		return current.sameHost
	}
	return current.depth < best.depth
}

// namesAnAPI reports a path whose segments mark it as an API root.
func namesAnAPI(segments []string) bool {
	for _, segment := range segments {
		lowered := strings.ToLower(segment)
		if _, exists := apiSegments[lowered]; exists {
			return true
		}
		if strings.HasSuffix(lowered, "api") || strings.HasSuffix(lowered, "apis") {
			return true
		}
	}
	return false
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
	prefix := "/" + strings.Trim(parsed.EscapedPath(), "/")
	if prefix == "/" {
		prefix = ""
	}
	return origin, prefix, nil
}

// BaseCandidatesInScope keeps only the origins belonging to an analyzed host or a subdomain of one.
func BaseCandidatesInScope(candidates []string, targetHosts []string, ignoreCrossDomain bool) []string {
	if !ignoreCrossDomain || len(targetHosts) == 0 {
		return candidates
	}

	kept := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		parsed, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		for _, target := range targetHosts {
			target = strings.ToLower(target)
			if host == target || strings.HasSuffix(host, "."+target) {
				kept = append(kept, candidate)
				break
			}
		}
	}
	return kept
}
