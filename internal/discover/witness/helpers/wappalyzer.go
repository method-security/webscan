package witnesshelpers

import (
	// Standard
	"bytes"
	"sort"
	"strings"
	"sync"

	// Generated
	discover "github.com/Method-Security/webscan/generated/go/discover"
	// External
	"github.com/PuerkitoBio/goquery"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const versionSeparator = ":"

type technologyBucket int

const (
	technologyBucketOther technologyBucket = iota
	technologyBucketClientSide
	technologyBucketServerSide
)

var (
	wappalyzeOnce     sync.Once
	wappalyzeInstance *wappalyzer.Wappalyze
	wappalyzeErr      error
)

var explicitTechnologyTypes = map[string]discover.DetectedTechnologyType{
	// Client-side ontology types.
	"alpine.js":          discover.DetectedTechnologyTypeUiFramework,
	"angular":            discover.DetectedTechnologyTypeUiFramework,
	"angularjs":          discover.DetectedTechnologyTypeUiFramework,
	"ember.js":           discover.DetectedTechnologyTypeUiFramework,
	"preact":             discover.DetectedTechnologyTypeUiFramework,
	"react":              discover.DetectedTechnologyTypeUiFramework,
	"solid":              discover.DetectedTechnologyTypeUiFramework,
	"solid.js":           discover.DetectedTechnologyTypeUiFramework,
	"svelte":             discover.DetectedTechnologyTypeUiFramework,
	"vue.js":             discover.DetectedTechnologyTypeUiFramework,
	"bootstrap":          discover.DetectedTechnologyTypeCssFramework,
	"bulma":              discover.DetectedTechnologyTypeCssFramework,
	"foundation":         discover.DetectedTechnologyTypeCssFramework,
	"materialize css":    discover.DetectedTechnologyTypeCssFramework,
	"semantic ui":        discover.DetectedTechnologyTypeCssFramework,
	"tailwind css":       discover.DetectedTechnologyTypeCssFramework,
	"amplitude":          discover.DetectedTechnologyTypeClientAnalytics,
	"google analytics":   discover.DetectedTechnologyTypeClientAnalytics,
	"google tag manager": discover.DetectedTechnologyTypeClientAnalytics,
	"heap":               discover.DetectedTechnologyTypeClientAnalytics,
	"hotjar":             discover.DetectedTechnologyTypeClientAnalytics,
	"matomo analytics":   discover.DetectedTechnologyTypeClientAnalytics,
	"mixpanel":           discover.DetectedTechnologyTypeClientAnalytics,
	"plausible":          discover.DetectedTechnologyTypeClientAnalytics,
	"segment":            discover.DetectedTechnologyTypeClientAnalytics,
	"drift":              discover.DetectedTechnologyTypeClientWidget,
	"hcaptcha":           discover.DetectedTechnologyTypeClientWidget,
	"intercom":           discover.DetectedTechnologyTypeClientWidget,
	"recaptcha":          discover.DetectedTechnologyTypeClientWidget,
	"stripe":             discover.DetectedTechnologyTypeClientWidget,
	"zendesk chat":       discover.DetectedTechnologyTypeClientWidget,

	// Server-side ontology types.
	"asp.net":         discover.DetectedTechnologyTypeWebFramework,
	"django":          discover.DetectedTechnologyTypeWebFramework,
	"express":         discover.DetectedTechnologyTypeWebFramework,
	"fastapi":         discover.DetectedTechnologyTypeWebFramework,
	"flask":           discover.DetectedTechnologyTypeWebFramework,
	"gin":             discover.DetectedTechnologyTypeWebFramework,
	"laravel":         discover.DetectedTechnologyTypeWebFramework,
	"nestjs":          discover.DetectedTechnologyTypeWebFramework,
	"next.js":         discover.DetectedTechnologyTypeWebFramework,
	"nuxt.js":         discover.DetectedTechnologyTypeWebFramework,
	"ruby on rails":   discover.DetectedTechnologyTypeWebFramework,
	"spring":          discover.DetectedTechnologyTypeWebFramework,
	"symfony":         discover.DetectedTechnologyTypeWebFramework,
	"bun":             discover.DetectedTechnologyTypeRuntime,
	"cpython":         discover.DetectedTechnologyTypeRuntime,
	"deno":            discover.DetectedTechnologyTypeRuntime,
	".net clr":        discover.DetectedTechnologyTypeRuntime,
	"jvm":             discover.DetectedTechnologyTypeRuntime,
	"node.js":         discover.DetectedTechnologyTypeRuntime,
	"php-fpm":         discover.DetectedTechnologyTypeRuntime,
	"ruby mri":        discover.DetectedTechnologyTypeRuntime,
	"ejs":             discover.DetectedTechnologyTypeTemplateEngine,
	"erb":             discover.DetectedTechnologyTypeTemplateEngine,
	"freemarker":      discover.DetectedTechnologyTypeTemplateEngine,
	"handlebars":      discover.DetectedTechnologyTypeTemplateEngine,
	"jinja2":          discover.DetectedTechnologyTypeTemplateEngine,
	"mustache":        discover.DetectedTechnologyTypeTemplateEngine,
	"pug":             discover.DetectedTechnologyTypeTemplateEngine,
	"thymeleaf":       discover.DetectedTechnologyTypeTemplateEngine,
	"twig":            discover.DetectedTechnologyTypeTemplateEngine,
	"auth0":           discover.DetectedTechnologyTypeAuthenticationLibrary,
	"devise":          discover.DetectedTechnologyTypeAuthenticationLibrary,
	"firebase auth":   discover.DetectedTechnologyTypeAuthenticationLibrary,
	"nextauth.js":     discover.DetectedTechnologyTypeAuthenticationLibrary,
	"passport":        discover.DetectedTechnologyTypeAuthenticationLibrary,
	"spring security": discover.DetectedTechnologyTypeAuthenticationLibrary,
}

// wappalyzerCategoryTypes gives every category in the vendored Wappalyzer
// catalog an explicit ontology disposition. Nil means the category does not
// map to the client/server ontology and should remain in the Other bucket.
var wappalyzerCategoryTypes = map[string]*discover.DetectedTechnologyType{
	"CMS":                             nil,
	"Message boards":                  nil,
	"Database managers":               nil,
	"Documentation":                   nil,
	"Widgets":                         technologyTypePtr(discover.DetectedTechnologyTypeClientWidget),
	"Ecommerce":                       nil,
	"Photo galleries":                 nil,
	"Wikis":                           nil,
	"Hosting panels":                  nil,
	"Analytics":                       technologyTypePtr(discover.DetectedTechnologyTypeClientAnalytics),
	"Blogs":                           nil,
	"JavaScript frameworks":           technologyTypePtr(discover.DetectedTechnologyTypeUiFramework),
	"Issue trackers":                  nil,
	"Video players":                   nil,
	"Comment systems":                 technologyTypePtr(discover.DetectedTechnologyTypeClientWidget),
	"Security":                        nil,
	"Font scripts":                    nil,
	"Web frameworks":                  technologyTypePtr(discover.DetectedTechnologyTypeWebFramework),
	"Miscellaneous":                   nil,
	"Editors":                         nil,
	"LMS":                             nil,
	"Web servers":                     nil,
	"Caching":                         nil,
	"Rich text editors":               nil,
	"JavaScript graphics":             technologyTypePtr(discover.DetectedTechnologyTypeJavascriptLibrary),
	"Mobile frameworks":               technologyTypePtr(discover.DetectedTechnologyTypeUiFramework),
	"Programming languages":           technologyTypePtr(discover.DetectedTechnologyTypeProgrammingLanguage),
	"Operating systems":               nil,
	"Search engines":                  nil,
	"Webmail":                         nil,
	"CDN":                             nil,
	"Marketing automation":            nil,
	"Web server extensions":           nil,
	"Databases":                       nil,
	"Maps":                            nil,
	"Advertising":                     nil,
	"Network devices":                 nil,
	"Media servers":                   nil,
	"Webcams":                         nil,
	"Payment processors":              nil,
	"Tag managers":                    technologyTypePtr(discover.DetectedTechnologyTypeClientAnalytics),
	"CI":                              nil,
	"Control systems":                 nil,
	"Remote access":                   nil,
	"Development":                     nil,
	"Network storage":                 nil,
	"Feed readers":                    nil,
	"DMS":                             nil,
	"Page builders":                   nil,
	"Live chat":                       technologyTypePtr(discover.DetectedTechnologyTypeClientWidget),
	"CRM":                             nil,
	"SEO":                             nil,
	"Accounting":                      nil,
	"Cryptominers":                    nil,
	"Static site generator":           nil,
	"User onboarding":                 nil,
	"JavaScript libraries":            technologyTypePtr(discover.DetectedTechnologyTypeJavascriptLibrary),
	"Containers":                      nil,
	"PaaS":                            nil,
	"IaaS":                            nil,
	"Reverse proxies":                 nil,
	"Load balancers":                  nil,
	"UI frameworks":                   technologyTypePtr(discover.DetectedTechnologyTypeUiFramework),
	"Cookie compliance":               nil,
	"Accessibility":                   nil,
	"Authentication":                  technologyTypePtr(discover.DetectedTechnologyTypeAuthenticationLibrary),
	"SSL/TLS certificate authorities": nil,
	"Affiliate programs":              nil,
	"Appointment scheduling":          nil,
	"Surveys":                         nil,
	"A/B Testing":                     nil,
	"Email":                           nil,
	"Personalisation":                 nil,
	"Retargeting":                     nil,
	"RUM":                             technologyTypePtr(discover.DetectedTechnologyTypeClientAnalytics),
	"Geolocation":                     nil,
	"WordPress themes":                nil,
	"Shopify themes":                  nil,
	"Drupal themes":                   nil,
	"Browser fingerprinting":          technologyTypePtr(discover.DetectedTechnologyTypeClientAnalytics),
	"Loyalty & rewards":               nil,
	"Feature management":              nil,
	"Segmentation":                    nil,
	"WordPress plugins":               nil,
	"Hosting":                         nil,
	"Translation":                     nil,
	"Reviews":                         nil,
	"Buy now pay later":               nil,
	"Performance":                     nil,
	"Reservations & delivery":         nil,
	"Referral marketing":              nil,
	"Digital asset management":        nil,
	"Content curation":                nil,
	"Customer data platform":          nil,
	"Cart abandonment":                nil,
	"Shipping carriers":               nil,
	"Shopify apps":                    nil,
	"Recruitment & staffing":          nil,
	"Returns":                         nil,
	"Livestreaming":                   nil,
	"Ticket booking":                  nil,
	"Augmented reality":               nil,
	"Cross border ecommerce":          nil,
	"Fulfilment":                      nil,
	"Ecommerce frontends":             nil,
	"Domain parking":                  nil,
	"Form builders":                   nil,
	"Fundraising & donations":         nil,
}

// categoryTypePriority preserves the prior category precedence for
// technologies that carry multiple Wappalyzer categories.
var categoryTypePriority = []string{
	"Web frameworks",
	"Programming languages",
	"Authentication",
	"UI frameworks",
	"JavaScript frameworks",
	"Mobile frameworks",
	"JavaScript libraries",
	"JavaScript graphics",
	"Analytics",
	"RUM",
	"Tag managers",
	"Browser fingerprinting",
	"Widgets",
	"Live chat",
	"Comment systems",
}

// getWappalyze returns the cached singleton wappalyzer instance.
func getWappalyze() (*wappalyzer.Wappalyze, error) {
	wappalyzeOnce.Do(func() {
		wappalyzeInstance, wappalyzeErr = wappalyzer.New()
	})
	return wappalyzeInstance, wappalyzeErr
}

// Fingerprint runs Wappalyzer fingerprinting on the provided headers and body,
// returning ontology-aligned client-side, server-side, and uncategorized buckets.
func Fingerprint(headers map[string][]string, body []byte) (*discover.DiscoverWitnessTechnologies, error) {
	wap, err := getWappalyze()
	if err != nil {
		return nil, err
	}

	appInfoMap := wap.FingerprintWithInfo(headers, body)
	mergeAppInfo(appInfoMap, fingerprintDOM(wap, body))

	technologies := &discover.DiscoverWitnessTechnologies{}
	keys := make([]string, 0, len(appInfoMap))
	for nameVersion := range appInfoMap {
		keys = append(keys, nameVersion)
	}
	sort.Strings(keys)

	for _, nameVersion := range keys {
		info := appInfoMap[nameVersion]
		tech := &discover.DetectedTechnology{}
		rawName := nameVersion

		// Parse "name:version" or just "name"
		if idx := strings.Index(nameVersion, versionSeparator); idx != -1 {
			rawName = nameVersion[:idx]
			name := normalizeTechnologyName(rawName)
			version := nameVersion[idx+1:]
			tech.SetName(name)
			if version != "" {
				tech.Version = &version
			}
		} else {
			tech.SetName(normalizeTechnologyName(nameVersion))
		}

		// Populate categories
		categories := append([]string(nil), info.Categories...)
		if categories == nil {
			categories = []string{}
		}
		sort.Strings(categories)
		tech.SetCategories(categories)
		bucket, technologyType := classifyTechnology(rawName, categories)
		tech.SetTechnologyType(technologyType)

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

		switch bucket {
		case technologyBucketClientSide:
			technologies.ClientSide = append(technologies.ClientSide, tech)
		case technologyBucketServerSide:
			technologies.ServerSide = append(technologies.ServerSide, tech)
		default:
			technologies.Other = append(technologies.Other, tech)
		}
	}

	return technologies, nil
}

// fingerprintDOM supplements wappalyzergo's header/body pass with the DOM
// rules in the embedded catalog. The upstream FingerprintWithInfo API does not
// evaluate DOM rules, but headless captures already return rendered HTML, so
// selectors such as Angular's [ng-version] are available here.
func fingerprintDOM(wap *wappalyzer.Wappalyze, body []byte) map[string]wappalyzer.AppInfo {
	result := make(map[string]wappalyzer.AppInfo)
	if len(body) == 0 {
		return result
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return result
	}

	for app, fingerprint := range wap.GetCompiledFingerprints().Apps {
		var matched bool
		var version string

		for selector, rules := range fingerprint.GetDOMRules() {
			selection := doc.Find(selector)
			if selection.Length() == 0 {
				continue
			}

			for ruleName, pattern := range rules {
				if pattern == nil || pattern.Confidence == 0 {
					continue
				}

				selection.EachWithBreak(func(_ int, element *goquery.Selection) bool {
					value := element.Text()
					if ruleName != "main" {
						var ok bool
						value, ok = element.Attr(ruleName)
						if !ok {
							return true
						}
					}

					valid, candidateVersion := pattern.Evaluate(strings.ToLower(value))
					if !valid {
						return true
					}

					matched = true
					if candidateVersion != "" && (version == "" || len(candidateVersion) > len(version)) {
						version = candidateVersion
					}
					return false
				})
			}
		}

		if matched {
			nameVersion := wappalyzer.FormatAppVersion(app, version)
			result[nameVersion] = wappalyzer.AppInfoFromFingerprint(fingerprint)
		}
	}

	return result
}

func mergeAppInfo(dst, src map[string]wappalyzer.AppInfo) {
	for nameVersion, info := range src {
		baseName := nameVersion
		if idx := strings.Index(nameVersion, versionSeparator); idx != -1 {
			baseName = nameVersion[:idx]
		}

		hasVersionedEntry := false
		for existing := range dst {
			if idx := strings.Index(existing, versionSeparator); idx != -1 {
				if existing[:idx] == baseName {
					hasVersionedEntry = true
				}
			}
		}

		if nameVersion == baseName && hasVersionedEntry {
			continue
		}
		if nameVersion != baseName {
			delete(dst, baseName)
		}
		dst[nameVersion] = info
	}
}

func classifyTechnology(name string, categories []string) (technologyBucket, discover.DetectedTechnologyType) {
	if technologyType, ok := explicitTechnologyTypes[strings.ToLower(strings.TrimSpace(name))]; ok {
		return bucketForTechnologyType(technologyType), technologyType
	}

	categorySet := make(map[string]struct{}, len(categories))
	for _, category := range categories {
		categorySet[category] = struct{}{}
	}

	for _, category := range categoryTypePriority {
		if _, ok := categorySet[category]; !ok {
			continue
		}
		technologyType := wappalyzerCategoryTypes[category]
		if technologyType != nil {
			return bucketForTechnologyType(*technologyType), *technologyType
		}
	}

	return technologyBucketOther, discover.DetectedTechnologyTypeUncategorized
}

func bucketForTechnologyType(technologyType discover.DetectedTechnologyType) technologyBucket {
	switch technologyType {
	case discover.DetectedTechnologyTypeUiFramework,
		discover.DetectedTechnologyTypeJavascriptLibrary,
		discover.DetectedTechnologyTypeCssFramework,
		discover.DetectedTechnologyTypeClientAnalytics,
		discover.DetectedTechnologyTypeClientWidget:
		return technologyBucketClientSide
	case discover.DetectedTechnologyTypeProgrammingLanguage,
		discover.DetectedTechnologyTypeWebFramework,
		discover.DetectedTechnologyTypeRuntime,
		discover.DetectedTechnologyTypeTemplateEngine,
		discover.DetectedTechnologyTypeAuthenticationLibrary:
		return technologyBucketServerSide
	default:
		return technologyBucketOther
	}
}

func technologyTypePtr(technologyType discover.DetectedTechnologyType) *discover.DetectedTechnologyType {
	return &technologyType
}

func normalizeTechnologyName(name string) string {
	return strings.Join(strings.Fields(strings.ToUpper(name)), "_")
}
