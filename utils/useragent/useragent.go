// Package useragent resolves User-Agent strings from a preset enum.
//
// The resolved UA is cached for the lifetime of the process so every
// request in a single CLI invocation sends the same UA. Without this,
// commands that issue multiple requests (e.g. probe trying HTTP then
// HTTPS) would send different random UAs from the same scan, an
// inconsistency that bot-detection systems flag. A new process gets a
// fresh pick.
package useragent

import (
	"sync"

	common "github.com/Method-Security/webscan/generated/go/common"
	pdua "github.com/projectdiscovery/useragent"
)

const fallback = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var (
	cached     string
	cachedOnce sync.Once
)

// Resolve returns a User-Agent string for the given preset. If preset is
// the zero value (empty string) or RANDOM, a random browser UA is picked.
// The result is resolved once per process and reused for all subsequent calls.
func Resolve(preset common.UserAgentPreset) string {
	cachedOnce.Do(func() {
		cached = pick(preset)
	})
	return cached
}

func pick(preset common.UserAgentPreset) string {
	if preset == "" || preset == common.UserAgentPresetRandom {
		return pickRandom()
	}
	switch preset {
	case common.UserAgentPresetChrome:
		// Edge UAs are also tagged "Chrome" because Edge is Chromium-based.
		// Exclude them so we only pick genuine Chrome UAs.
		return pickByFilter(func(ua *pdua.UserAgent) bool {
			return pdua.ContainsTagsAny(ua, "Chrome", "Chromium") && !pdua.ContainsTagsAny(ua, "Edge")
		})
	case common.UserAgentPresetFirefox:
		return pickByFilter(pdua.Mozilla)
	case common.UserAgentPresetSafari:
		// Chrome and Edge UAs are also tagged "Safari" because they forked from WebKit.
		// Exclude them so we only pick genuine Safari UAs.
		return pickByFilter(func(ua *pdua.UserAgent) bool {
			return pdua.ContainsTags(ua, "Safari") && !pdua.ContainsTagsAny(ua, "Chrome", "Chromium", "Edge")
		})
	case common.UserAgentPresetEdge:
		return pickByFilter(func(ua *pdua.UserAgent) bool {
			return pdua.ContainsTagsAny(ua, "Edge")
		})
	default:
		return pickRandom()
	}
}

func pickRandom() string {
	if ua := pdua.PickRandom(); ua != nil {
		return ua.Raw
	}
	return fallback
}

func pickByFilter(filter pdua.Filter) string {
	uas, err := pdua.PickWithFilters(1, filter)
	if err == nil && len(uas) > 0 {
		return uas[0].Raw
	}
	return pickRandom()
}
