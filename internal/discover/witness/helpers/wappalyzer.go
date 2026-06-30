package witnesshelpers

import (
	// Standard
	"strings"
	"sync"

	// Generated
	discover "github.com/Method-Security/webscan/generated/go/discover"
	// External
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const versionSeparator = ":"

var (
	wappalyzeOnce     sync.Once
	wappalyzeInstance *wappalyzer.Wappalyze
	wappalyzeErr      error
)

// getWappalyze returns the cached singleton wappalyzer instance.
func getWappalyze() (*wappalyzer.Wappalyze, error) {
	wappalyzeOnce.Do(func() {
		wappalyzeInstance, wappalyzeErr = wappalyzer.New()
	})
	return wappalyzeInstance, wappalyzeErr
}

// Fingerprint runs Wappalyzer fingerprinting on the provided headers and body,
// returning a slice of DetectedTechnology Fern types.
func Fingerprint(headers map[string][]string, body []byte) ([]*discover.DetectedTechnology, error) {
	wap, err := getWappalyze()
	if err != nil {
		return nil, err
	}

	appInfoMap := wap.FingerprintWithInfo(headers, body)

	technologies := make([]*discover.DetectedTechnology, 0, len(appInfoMap))
	for nameVersion, info := range appInfoMap {
		tech := &discover.DetectedTechnology{}

		// Parse "name:version" or just "name"
		if idx := strings.Index(nameVersion, versionSeparator); idx != -1 {
			name := nameVersion[:idx]
			version := nameVersion[idx+1:]
			tech.SetName(name)
			if version != "" {
				tech.Version = &version
			}
		} else {
			tech.SetName(nameVersion)
		}

		// Populate categories
		categories := info.Categories
		if categories == nil {
			categories = []string{}
		}
		tech.SetCategories(categories)

		// Populate optional fields
		if info.CPE != "" {
			cpe := info.CPE
			tech.Cpe = &cpe
		}
		if info.Description != "" {
			desc := info.Description
			tech.Description = &desc
		}
		if info.Website != "" {
			site := info.Website
			tech.Website = &site
		}

		technologies = append(technologies, tech)
	}

	return technologies, nil
}
