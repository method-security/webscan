package enumeratejavascript

import (
	// Standard
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/enumerate"

	// External
	"github.com/BishopFox/jsluice"
)

// DefaultWindowBytes bounds one parse. tree-sitter recovers poorly on multi-megabyte minified
// bundles and silently yields nothing, so source is analyzed in windows rather than whole.
const DefaultWindowBytes = 256 * 1024

// DefaultWindowOverlapBytes keeps a call split by a window boundary visible to one of the windows.
const DefaultWindowOverlapBytes = 64 * 1024

// Analysis is everything one JavaScript artifact yielded.
type Analysis struct {
	Endpoints []*enumerate.JavascriptEndpoint
	Secrets   []*enumerate.JavascriptSecret
	Origins   []string
}

var nonEndpointSuffixes = []string{
	".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".otf", ".eot", ".webp", ".mp4", ".webm",
}

// AnalyzeSource extracts endpoints, secrets and origins from one artifact's source.
func AnalyzeSource(source []byte, sourceURL string, windowBytes int, overlapBytes int) Analysis {
	if windowBytes <= 0 {
		windowBytes = DefaultWindowBytes
	}
	if overlapBytes < 0 || overlapBytes >= windowBytes {
		overlapBytes = windowBytes / 4
	}

	endpoints := map[string]*enumerate.JavascriptEndpoint{}
	secrets := map[string]*enumerate.JavascriptSecret{}
	bases := map[string]struct{}{}

	for _, window := range windowsOf(len(source), windowBytes, overlapBytes) {
		analyzer := jsluice.NewAnalyzer(source[window[0]:window[1]])

		for _, found := range analyzer.GetURLs() {
			if found == nil {
				continue
			}
			if base, ok := absoluteBase(found.URL); ok {
				bases[base] = struct{}{}
			}
			endpoint := toEndpoint(found, sourceURL)
			if endpoint == nil {
				continue
			}
			if _, exists := endpoints[endpointKey(endpoint)]; !exists {
				endpoints[endpointKey(endpoint)] = endpoint
			}
		}

		for _, found := range analyzer.GetSecrets() {
			if found == nil {
				continue
			}
			secret := toSecret(found, sourceURL)
			if _, exists := secrets[secretKey(secret)]; !exists {
				secrets[secretKey(secret)] = secret
			}
		}
	}

	return Analysis{
		Endpoints: mergeEndpointRecords(sortedEndpoints(endpoints)),
		Secrets:   sortedSecrets(secrets),
		Origins:   sortedKeys(bases),
	}
}

// windowsOf returns [start, end) offsets covering size with the requested overlap.
func windowsOf(size int, windowBytes int, overlapBytes int) [][2]int {
	if size == 0 {
		return nil
	}
	if size <= windowBytes {
		return [][2]int{{0, size}}
	}

	stride := windowBytes - overlapBytes
	if stride <= 0 {
		stride = windowBytes
	}

	var windows [][2]int
	for start := 0; start < size; start += stride {
		end := start + windowBytes
		if end >= size {
			windows = append(windows, [2]int{start, size})
			break
		}
		windows = append(windows, [2]int{start, end})
	}
	return windows
}

// toEndpoint converts a jsluice URL into an endpoint, dropping references that are not requests.
func toEndpoint(found *jsluice.URL, sourceURL string) *enumerate.JavascriptEndpoint {
	raw := strings.TrimSpace(found.URL)
	if raw == "" {
		return nil
	}

	path := raw
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
	}
	if path == "" {
		return nil
	}

	endpoint := &enumerate.JavascriptEndpoint{
		Path:        path,
		SourceUrl:   sourceURL,
		QueryParams: found.QueryParams,
		BodyParams:  found.BodyParams,
	}
	if found.ContentType != "" {
		endpoint.ContentType = &found.ContentType
	}
	if found.Type != "" && found.Type != "stringLiteral" {
		callExpression := found.Type
		endpoint.CallExpression = &callExpression
	}
	if method, ok := requestMethod(found.Method); ok {
		endpoint.Method = &method
	} else if method, ok := methodFromCall(found.Type); ok {
		endpoint.Method = &method
	}

	if base, ok := absoluteOrigin(raw); ok {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil
		}
		// A bare origin names no endpoint; it is only ever a base candidate.
		if parsed.Path == "" || parsed.Path == "/" {
			return nil
		}
		if isNonEndpointPath(parsed.Path) {
			return nil
		}
		endpoint.BaseUrl = &base
		endpoint.Path = parsed.Path
		endpoint.Rooted = true
		return endpoint
	}

	if isNonEndpointPath(path) {
		return nil
	}
	if strings.HasPrefix(path, "//") {
		return nil
	}
	if strings.HasPrefix(path, "/") {
		endpoint.Rooted = true
		return endpoint
	}
	// A bare literal is only an endpoint candidate when it reads as a path.
	if !strings.Contains(path, "/") {
		return nil
	}
	if strings.HasPrefix(path, ".") || strings.Contains(path, " ") {
		return nil
	}
	return endpoint
}

// toSecret converts a jsluice secret, rendering its payload as JSON so no structure is lost.
func toSecret(found *jsluice.Secret, sourceURL string) *enumerate.JavascriptSecret {
	secret := &enumerate.JavascriptSecret{
		Kind:      found.Kind,
		Severity:  secretSeverity(found.Severity),
		SourceUrl: sourceURL,
	}
	if rendered := renderJSON(found.Data); rendered != "" {
		secret.Value = &rendered
	}
	if rendered := renderJSON(found.Context); rendered != "" {
		secret.Context = &rendered
	}
	return secret
}

func renderJSON(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func secretSeverity(severity jsluice.Severity) enumerate.JavascriptSecretSeverity {
	switch severity {
	case jsluice.SeverityHigh:
		return enumerate.JavascriptSecretSeverityHigh
	case jsluice.SeverityMedium:
		return enumerate.JavascriptSecretSeverityMedium
	case jsluice.SeverityLow:
		return enumerate.JavascriptSecretSeverityLow
	default:
		return enumerate.JavascriptSecretSeverityInfo
	}
}

// requestMethod maps a jsluice method onto an HTTP verb, ignoring the call expressions it reports
// when the verb is not stated.
func requestMethod(method string) (common.HttpMethod, bool) {
	trimmed := strings.ToUpper(strings.TrimSpace(method))
	if trimmed == "" {
		return "", false
	}
	parsed, err := common.NewHttpMethodFromString(trimmed)
	if err != nil {
		return "", false
	}
	return parsed, true
}

// methodFromCall reads the verb off a client call such as `this.http.post`.
//
// Only an exact verb is taken. A wrapper like `getRequest` names its verb loosely enough that
// reading one off it would be a guess, and the call expression already records it.
func methodFromCall(callExpression string) (common.HttpMethod, bool) {
	if callExpression == "" {
		return "", false
	}
	segments := strings.Split(callExpression, ".")
	return requestMethod(segments[len(segments)-1])
}

// absoluteBase returns an absolute http(s) URL without its query or fragment.
func absoluteBase(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimSuffix(parsed.String(), "/"), true
}

// mergeEndpointRecords collapses the several records jsluice emits for one call.
//
// The same call is reported with and without its verb, and again as a bare string literal. A record
// carrying the verb is the complete one, so at a given location the verbless records are dropped
// once any record states a verb.
func mergeEndpointRecords(endpoints []*enumerate.JavascriptEndpoint) []*enumerate.JavascriptEndpoint {
	locationHasMethod := map[string]bool{}
	for _, endpoint := range endpoints {
		if endpoint.Method != nil {
			locationHasMethod[locationKey(endpoint)] = true
		}
	}

	merged := map[string]*enumerate.JavascriptEndpoint{}
	order := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Method == nil && locationHasMethod[locationKey(endpoint)] {
			continue
		}

		key := endpointKey(endpoint)
		existing, exists := merged[key]
		if !exists {
			merged[key] = endpoint
			order = append(order, key)
			continue
		}
		if existing.CallExpression == nil && endpoint.CallExpression != nil {
			existing.CallExpression = endpoint.CallExpression
		}
		if existing.ContentType == nil && endpoint.ContentType != nil {
			existing.ContentType = endpoint.ContentType
		}
		existing.QueryParams = unionStrings(existing.QueryParams, endpoint.QueryParams)
		existing.BodyParams = unionStrings(existing.BodyParams, endpoint.BodyParams)
	}

	sort.Strings(order)
	out := make([]*enumerate.JavascriptEndpoint, 0, len(order))
	for _, key := range order {
		out = append(out, merged[key])
	}
	return out
}

func unionStrings(first []string, second []string) []string {
	if len(second) == 0 {
		return first
	}
	seen := map[string]struct{}{}
	for _, value := range first {
		seen[value] = struct{}{}
	}
	out := first
	for _, value := range second {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func locationKey(endpoint *enumerate.JavascriptEndpoint) string {
	base := ""
	if endpoint.BaseUrl != nil {
		base = *endpoint.BaseUrl
	}
	return base + endpoint.Path
}

// absoluteOrigin returns the scheme and host of an absolute http(s) URL.
func absoluteOrigin(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	return parsed.Scheme + "://" + parsed.Host, true
}

func isNonEndpointPath(path string) bool {
	lowered := strings.ToLower(path)
	for _, suffix := range nonEndpointSuffixes {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	return false
}

func endpointKey(endpoint *enumerate.JavascriptEndpoint) string {
	base := ""
	if endpoint.BaseUrl != nil {
		base = *endpoint.BaseUrl
	}
	method := ""
	if endpoint.Method != nil {
		method = string(*endpoint.Method)
	}
	return method + " " + base + endpoint.Path
}

func secretKey(secret *enumerate.JavascriptSecret) string {
	value := ""
	if secret.Value != nil {
		value = *secret.Value
	}
	return secret.Kind + " " + value
}

func sortedEndpoints(endpoints map[string]*enumerate.JavascriptEndpoint) []*enumerate.JavascriptEndpoint {
	keys := make([]string, 0, len(endpoints))
	for key := range endpoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]*enumerate.JavascriptEndpoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, endpoints[key])
	}
	return out
}

func sortedSecrets(secrets map[string]*enumerate.JavascriptSecret) []*enumerate.JavascriptSecret {
	keys := make([]string, 0, len(secrets))
	for key := range secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]*enumerate.JavascriptSecret, 0, len(keys))
	for _, key := range keys {
		out = append(out, secrets[key])
	}
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
