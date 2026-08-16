package cms

import (
	// Standard
	"net/url"
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

// cmsProbeBaseURL returns the final scheme/host/port reached by the initial
// request. CMS probes are always rooted at that base URL instead of trying to
// infer an application root from a redirect path.
func cmsProbeBaseURL(original string, response *common.HttpRequestResponse) string {
	for _, target := range []string{canonicalTargetURL(original, response), original} {
		parsedURL, err := url.Parse(target)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			continue
		}
		return (&url.URL{
			Scheme: parsedURL.Scheme,
			Host:   parsedURL.Host,
		}).String()
	}
	return original
}
