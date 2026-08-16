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

// cmsProbeTargetURL keeps the final canonical origin while selecting a path that
// can safely be used as a CMS installation root. Redirects to page-like paths
// such as /wp-login.php or /user/login should not cause probes to be built under
// those pages.
func cmsProbeTargetURL(original string, response *common.HttpRequestResponse) string {
	canonical := canonicalTargetURL(original, response)

	originalURL, err := url.Parse(original)
	if err != nil {
		return canonical
	}
	canonicalURL, err := url.Parse(canonical)
	if err != nil {
		return original
	}

	if !isCMSDirectoryPath(canonicalURL.Path) && !sameNormalizedPath(originalURL.Path, canonicalURL.Path) {
		canonicalURL.Path = originalURL.Path
	}
	canonicalURL.RawQuery = ""
	canonicalURL.Fragment = ""
	return canonicalURL.String()
}

func isCMSDirectoryPath(path string) bool {
	return path == "" || path == "/" || strings.HasSuffix(path, "/")
}

func sameNormalizedPath(left, right string) bool {
	return strings.TrimRight(left, "/") == strings.TrimRight(right, "/")
}
