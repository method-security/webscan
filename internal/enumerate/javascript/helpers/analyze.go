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

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	// External
	"github.com/BishopFox/jsluice"
)

// DefaultWindowBytes bounds one parse. tree-sitter recovers poorly on multi-megabyte minified
// bundles and silently yields nothing, so source is analyzed in windows rather than whole.
const DefaultWindowBytes = 256 * 1024

// DefaultWindowOverlapBytes keeps a call split by a window boundary visible to one of the windows.
const DefaultWindowOverlapBytes = 64 * 1024

// MaxQueryParamValueBytes keeps embedded payload-like examples from bloating a JavaScript
// endpoint record.
const MaxQueryParamValueBytes = 256

// Analysis is everything one JavaScript artifact yielded.
type Analysis struct {
	Endpoints []*Endpoint
	Secrets   []*enumerate.JavascriptSecret
	Origins   []string
}

// Endpoint is an extracted endpoint, the origin serving it and whether that origin is established.
// Both are stages of the extraction: the origin is reported as the application the endpoint sits
// under, and rooted is not reported at all.
type Endpoint struct {
	Details *enumerate.JavascriptEndpoint
	BaseURL string
	Rooted  bool
}

// Clone copies an endpoint so an artifact shared by two applications roots once per application.
func (e *Endpoint) Clone() *Endpoint {
	details := *e.Details
	return &Endpoint{Details: &details, BaseURL: e.BaseURL, Rooted: e.Rooted}
}

// dataDocumentSuffixes name formats an API serves as readily as a file server does. They are static
// assets to a crawler deciding what to spider, but a request for one is still a request.
var dataDocumentSuffixes = []string{".json", ".xml", ".csv", ".txt", ".yaml", ".yml", ".md", ".markdown"}

// isNonEndpointAsset reports a path that names a file rather than something worth requesting.
//
// The asset list is shared with the crawler so the two agree on what an asset is, less the data
// documents, which an application requests from its API as often as it serves them as files.
func isNonEndpointAsset(path string) bool {
	if !utils.IsStaticAsset(path) {
		return false
	}
	trimmed := strings.ToLower(path)
	if cut := strings.IndexAny(trimmed, "?#"); cut >= 0 {
		trimmed = trimmed[:cut]
	}
	for _, suffix := range dataDocumentSuffixes {
		if strings.HasSuffix(trimmed, suffix) {
			return false
		}
	}
	return true
}

// AnalyzeSource extracts endpoints, secrets and origins from one artifact's source.
func AnalyzeSource(source []byte, sourceURL string, windowBytes int, overlapBytes int) Analysis {
	if windowBytes <= 0 {
		windowBytes = DefaultWindowBytes
	}
	if overlapBytes < 0 || overlapBytes >= windowBytes {
		overlapBytes = windowBytes / 4
	}

	endpoints := map[string]*Endpoint{}
	secrets := map[string]*enumerate.JavascriptSecret{}
	bases := map[string]struct{}{}

	for _, window := range windowsOf(len(source), windowBytes, overlapBytes) {
		analyzer := jsluice.NewAnalyzer(source[window[0]:window[1]])
		analyzer.AddSecretMatcher(CredentialMatcher())

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
			key := endpointKey(endpoint)
			if existing, exists := endpoints[key]; exists {
				// One call site may state a parameter another omits, and windows overlap, so a
				// repeat is extra evidence about the same endpoint rather than a duplicate to drop.
				mergeEndpointDetails(existing, endpoint)
			} else {
				endpoints[key] = endpoint
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
func toEndpoint(found *jsluice.URL, sourceURL string) *Endpoint {
	raw := strings.TrimSpace(found.URL)
	if raw == "" {
		return nil
	}

	path := raw
	query := ""
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		if path[cut] == '?' {
			query = path[cut+1:]
			if end := strings.IndexByte(query, '#'); end >= 0 {
				query = query[:end]
			}
		}
		path = path[:cut]
	}
	path, ok := normalizeTemplatePath(path)
	if !ok {
		return nil
	}
	if isMarkupFragmentPath(path) {
		return nil
	}

	details := &enumerate.JavascriptEndpoint{
		Path:        path,
		SourceUrl:   sourceURL,
		QueryParams: endpointParams(found.QueryParams, literalQueryValues(query)),
		BodyParams:  endpointParams(found.BodyParams, nil),
	}
	endpoint := &Endpoint{Details: details}
	if found.ContentType != "" {
		details.ContentType = &found.ContentType
	}
	if method, ok := requestMethod(found.Method); ok {
		details.Method = &method
	} else if method, ok := methodFromCall(found.Type); ok {
		details.Method = &method
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
		if isNonEndpointAsset(parsed.Path) {
			return nil
		}
		absolutePath, ok := normalizeTemplatePath(parsed.Path)
		if !ok {
			return nil
		}
		endpoint.BaseURL = base
		details.Path = absolutePath
		endpoint.Rooted = true
		return endpoint
	}

	if isNonEndpointAsset(path) {
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

func isMarkupFragmentPath(path string) bool {
	if strings.Contains(path, `\`) {
		return true
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		decoded = path
	}
	return strings.ContainsAny(decoded, "<>")
}

// toSecret converts a jsluice secret into typed fields, lifting out the name and value a matcher
// reports and leaving the rest addressable, since each matcher's payload has its own key set.
func toSecret(found *jsluice.Secret, sourceURL string) *enumerate.JavascriptSecret {
	secret := &enumerate.JavascriptSecret{
		Kind:       found.Kind,
		SourceUrl:  sourceURL,
		Attributes: map[string]string{},
		Context:    asStringMap(found.Context),
	}

	for key, value := range asStringMap(found.Data) {
		switch key {
		case "name":
			secret.Name = &value
		case "value", "key":
			secret.Value = &value
		default:
			secret.Attributes[key] = value
		}
	}

	if len(secret.Attributes) == 0 {
		secret.Attributes = nil
	}
	return secret
}

// asStringMap reduces a matcher payload to string pairs.
func asStringMap(value any) map[string]string {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]string:
		return typed
	case map[string]any:
		out := make(map[string]string, len(typed))
		for key, entry := range typed {
			if text, ok := entry.(string); ok {
				out[key] = text
				continue
			}
			if encoded, err := json.Marshal(entry); err == nil {
				out[key] = string(encoded)
			}
		}
		return out
	default:
		return nil
	}
}

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
func mergeEndpointRecords(endpoints []*Endpoint) []*Endpoint {
	locationHasMethod := map[string]bool{}
	for _, endpoint := range endpoints {
		if endpoint.Details.Method != nil {
			locationHasMethod[locationKey(endpoint)] = true
		}
	}

	merged := map[string]*Endpoint{}
	order := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Details.Method == nil && locationHasMethod[locationKey(endpoint)] {
			continue
		}

		key := endpointKey(endpoint)
		existing, exists := merged[key]
		if !exists {
			merged[key] = endpoint
			order = append(order, key)
			continue
		}
		mergeEndpointDetails(existing, endpoint)
	}

	sort.Strings(order)
	out := make([]*Endpoint, 0, len(order))
	for _, key := range order {
		out = append(out, merged[key])
	}
	return out
}

func locationKey(endpoint *Endpoint) string {
	return endpoint.BaseURL + endpoint.Details.Path
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

func endpointKey(endpoint *Endpoint) string {
	method := ""
	if endpoint.Details.Method != nil {
		method = string(*endpoint.Details.Method)
	}
	return method + " " + endpoint.BaseURL + endpoint.Details.Path
}

func secretKey(secret *enumerate.JavascriptSecret) string {
	name := ""
	if secret.Name != nil {
		name = *secret.Name
	}
	value := ""
	if secret.Value != nil {
		value = *secret.Value
	}
	return secret.Kind + " " + name + " " + value
}

func sortedEndpoints(endpoints map[string]*Endpoint) []*Endpoint {
	keys := make([]string, 0, len(endpoints))
	for key := range endpoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]*Endpoint, 0, len(keys))
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

// normalizeTemplatePath turns path parameters into explicit templates. A
// jsluice expression glued into a segment leaves a name nothing can recover, so it is dropped rather
// than emitted as an invented endpoint.
func normalizeTemplatePath(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if strings.Contains(segment, jsluice.ExpressionPlaceholder) {
			if segment != jsluice.ExpressionPlaceholder {
				return "", false
			}
			segments[i] = "{param}"
			continue
		}
		if normalized, ok := normalizeNamedPathSegment(segment); ok {
			segments[i] = normalized
			continue
		}
		if segment == "*" {
			segments[i] = "{wildcard}"
			continue
		}
		if strings.Contains(segment, "*") {
			segments[i] = strings.ReplaceAll(segment, "*", "{wildcard}")
			continue
		}
	}
	return strings.Join(segments, "/"), true
}

func normalizeNamedPathSegment(segment string) (string, bool) {
	if strings.HasPrefix(segment, ":") && len(segment) > 1 {
		name := strings.TrimPrefix(segment, ":")
		if wildcard := strings.IndexByte(name, '*'); wildcard >= 0 {
			return "{" + name[:wildcard] + "...}" + name[wildcard+1:], true
		}
		return "{" + name + "}", true
	}
	if strings.HasPrefix(segment, "[[...") && strings.HasSuffix(segment, "]]") {
		return "{" + strings.TrimSuffix(strings.TrimPrefix(segment, "[[..."), "]]") + "...}", true
	}
	if strings.HasPrefix(segment, "[...") && strings.HasSuffix(segment, "]") {
		return "{" + strings.TrimSuffix(strings.TrimPrefix(segment, "[..."), "]") + "...}", true
	}
	if strings.HasPrefix(segment, "[") && strings.HasSuffix(segment, "]") && len(segment) > 2 {
		return "{" + strings.TrimSuffix(strings.TrimPrefix(segment, "["), "]") + "}", true
	}
	return "", false
}

// literalQueryValues keeps the values a client hard-codes and drops the ones it computes. The
// placeholder means the value is supplied at runtime, so it is absent rather than empty: a probe
// has to generate one, and sending "EXPR" would be worse than sending nothing.
func literalQueryValues(query string) map[string]string {
	if query == "" {
		return nil
	}
	values := map[string]string{}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		name, value, found := strings.Cut(pair, "=")
		if !found || name == "" || value == "" {
			continue
		}
		if strings.Contains(value, jsluice.ExpressionPlaceholder) {
			continue
		}
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			decodedName = name
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			decodedValue = value
		}
		if len(decodedValue) > MaxQueryParamValueBytes {
			continue
		}
		values[decodedName] = decodedValue
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

// mergeEndpointDetails folds one record of an endpoint into another. Every field is additive: a
// field the existing record lacks is taken, and a field both carry keeps what was seen first.
func mergeEndpointDetails(existing *Endpoint, incoming *Endpoint) {
	if existing.Details.ContentType == nil && incoming.Details.ContentType != nil {
		existing.Details.ContentType = incoming.Details.ContentType
	}
	existing.Details.QueryParams = mergeEndpointParams(existing.Details.QueryParams, incoming.Details.QueryParams)
	existing.Details.BodyParams = mergeEndpointParams(existing.Details.BodyParams, incoming.Details.BodyParams)
}

func endpointParams(names []string, values map[string]string) []*enumerate.JavascriptEndpointParam {
	if len(names) == 0 {
		return nil
	}
	params := make([]*enumerate.JavascriptEndpointParam, 0, len(names))
	seen := map[string]struct{}{}
	for _, name := range names {
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		param := &enumerate.JavascriptEndpointParam{Name: name}
		if value, exists := values[name]; exists {
			param.ExampleValue = &value
		}
		params = append(params, param)
	}
	return params
}

// mergeEndpointParams keeps the first literal example seen for a parameter. Two call sites
// passing different constants both describe a real request, and one of them is as good a probe
// value as the other.
func mergeEndpointParams(existing []*enumerate.JavascriptEndpointParam, incoming []*enumerate.JavascriptEndpointParam) []*enumerate.JavascriptEndpointParam {
	if len(incoming) == 0 {
		return existing
	}
	byName := make(map[string]*enumerate.JavascriptEndpointParam, len(existing))
	for _, param := range existing {
		byName[param.Name] = param
	}
	for _, param := range incoming {
		if current, exists := byName[param.Name]; exists {
			if current.ExampleValue == nil && param.ExampleValue != nil {
				current.ExampleValue = param.ExampleValue
			}
			continue
		}
		existing = append(existing, param)
		byName[param.Name] = param
	}
	return existing
}
