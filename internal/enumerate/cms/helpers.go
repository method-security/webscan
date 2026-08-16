package cms

import (
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
)

const cmsInitialMaxRedirects = 10

// canonicalTargetURL returns the final URL reached by an initial CMS target
// request. Evidence probes use this path as the application root, while their
// own requests keep redirects disabled to avoid false positives.
func canonicalTargetURL(original string, response *common.HttpRequestResponse) string {
	if response == nil || response.Response == nil || len(response.Response.RedirectChain) == 0 {
		return original
	}
	return response.Response.RedirectChain[len(response.Response.RedirectChain)-1]
}
