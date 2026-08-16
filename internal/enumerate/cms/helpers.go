package cms

import (
	// Standard
	"net/url"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
)

const cmsInitialMaxRedirects = 10

// canonicalTargetURL returns the final URL reached by an initial CMS target request.
func canonicalTargetURL(original string, response *common.HttpRequestResponse) string {
	if response == nil || response.Response == nil || len(response.Response.RedirectChain) == 0 {
		return original
	}
	return response.Response.RedirectChain[len(response.Response.RedirectChain)-1]
}

// cmsProbeTargetURLs returns the deduplicated paths worth probing after the
// initial request. The final origin is retained for all probes, while both the
// landed path and the caller's original path are tried when they differ.
//
// URL shape alone cannot tell whether /wordpress is an install root or whether
// /wp-admin/ is just a page, so callers should let CMS-specific evidence decide.
func cmsProbeTargetURLs(original string, response *common.HttpRequestResponse) []string {
	canonical := canonicalTargetURL(original, response)

	canonicalURL, err := url.Parse(canonical)
	if err != nil {
		return []string{canonical}
	}
	originalURL, err := url.Parse(original)
	if err != nil {
		return []string{canonical}
	}

	candidates := make([]string, 0, 2)
	seen := make(map[string]bool, 2)
	for _, path := range []string{canonicalURL.Path, originalURL.Path} {
		candidate := *canonicalURL
		candidate.Path = normalizedCMSProbePath(path)
		candidate.RawPath = ""
		candidate.RawQuery = ""
		candidate.Fragment = ""

		candidateURL := candidate.String()
		if seen[candidateURL] {
			continue
		}
		seen[candidateURL] = true
		candidates = append(candidates, candidateURL)
	}

	return candidates
}

func normalizedCMSProbePath(path string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	return "/" + path
}
