package discoverroute

import (
	// Standard
	"fmt"
	"regexp"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
)

// DeclaredRouteEvidence marks a route the application itself declares, not one merely observed.
const DeclaredRouteEvidence = "route-table"

// Catch-alls are excluded: one placeholder cannot stand for the many segments they match.
var declaredParamPattern = regexp.MustCompile(`^(?::([A-Za-z_][A-Za-z0-9_]*)\??|\[([A-Za-z_][A-Za-z0-9_.]*)\]|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)

// DeclaredParamName returns the parameter a declaration segment names, if it names one.
func DeclaredParamName(segment string) (string, bool) {
	match := declaredParamPattern.FindStringSubmatch(segment)
	if match == nil {
		return "", false
	}
	for _, group := range match[1:] {
		if group != "" {
			return strings.TrimPrefix(group, "..."), true
		}
	}
	return "", false
}

// NormalizeDeclaredTemplate rewrites a declaration into the `{name}` form ConstructURL substitutes.
func NormalizeDeclaredTemplate(path string) (string, []*discover.RoutePathParam, bool) {
	segments := strings.Split(path, "/")
	params := make([]*discover.RoutePathParam, 0, len(segments))
	seen := map[string]struct{}{}

	for i, segment := range segments {
		name, isParam := DeclaredParamName(segment)
		if !isParam {
			continue
		}
		segments[i] = "{" + name + "}"
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		params = append(params, &discover.RoutePathParam{Name: name})
	}

	if len(params) == 0 {
		return path, nil, false
	}
	// Residual syntax means a segment was unconvertible, so the template is malformed.
	for _, segment := range segments {
		if segment == "" || strings.HasPrefix(segment, "{") {
			continue
		}
		if HasDeclaredParamSyntax("/" + segment) {
			return path, nil, false
		}
	}
	// Without a literal segment the template discriminates on segment count alone.
	if !hasLiteralSegment(segments) {
		return path, nil, false
	}
	return strings.Join(segments, "/"), params, true
}

// hasLiteralSegment reports whether any segment is fixed rather than a placeholder.
func hasLiteralSegment(segments []string) bool {
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if !strings.HasPrefix(segment, "{") {
			return true
		}
	}
	return false
}

var declaredParamSyntaxPattern = regexp.MustCompile(`(?:^|/)(?::[^/]+|\[[^/]*\]|\{[^/]*\})(?:/|$)`)

// HasDeclaredParamSyntax reports parameter syntax even in forms that yield no usable template.
func HasDeclaredParamSyntax(path string) bool {
	return declaredParamSyntaxPattern.MatchString(path)
}

// templateMatchesLiteral reports whether a literal instantiates a template, with its values.
func templateMatchesLiteral(template string, literal string) (map[string]string, bool) {
	templateSegments := strings.Split(template, "/")
	literalSegments := strings.Split(literal, "/")
	if len(templateSegments) != len(literalSegments) {
		return nil, false
	}

	values := map[string]string{}
	for i, templateSegment := range templateSegments {
		if !matchTemplateSegment(templateSegment, literalSegments[i], values) {
			return nil, false
		}
	}
	return values, true
}

// embeddedPlaceholderPattern matches a `{name}` placeholder anywhere within a segment.
var embeddedPlaceholderPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// A placeholder need not span the segment: `order_{orderId}.pdf` embeds one.
func matchTemplateSegment(templateSegment string, literalSegment string, values map[string]string) bool {
	if name, isParam := DeclaredParamName(templateSegment); isParam {
		if literalSegment == "" {
			return false
		}
		values[name] = literalSegment
		return true
	}

	locations := embeddedPlaceholderPattern.FindAllStringSubmatchIndex(templateSegment, -1)
	if len(locations) == 0 {
		return templateSegment == literalSegment
	}

	var names []string
	var pattern strings.Builder
	pattern.WriteString("^")
	previous := 0
	for _, location := range locations {
		pattern.WriteString(regexp.QuoteMeta(templateSegment[previous:location[0]]))
		pattern.WriteString("(.+?)")
		names = append(names, templateSegment[location[2]:location[3]])
		previous = location[1]
	}
	pattern.WriteString(regexp.QuoteMeta(templateSegment[previous:]))
	pattern.WriteString("$")

	matcher, err := regexp.Compile(pattern.String())
	if err != nil {
		return false
	}
	match := matcher.FindStringSubmatch(literalSegment)
	if match == nil {
		return false
	}
	for i, name := range names {
		values[name] = match[i+1]
	}
	return true
}

// ApplyDeclaredRouteTemplates folds observed literals into templates the application declares.
func ApplyDeclaredRouteTemplates(routes []*discover.RouteDetails) []*discover.RouteDetails {
	type templateRoute struct {
		route    *discover.RouteDetails
		template string
	}

	// An unrooted candidate carries a path resolution never confirmed, so it must not reach output.
	rooted := make([]*discover.RouteDetails, 0, len(routes))
	for _, route := range routes {
		if IsUnrootedEvidence(route.Evidence) {
			continue
		}
		rooted = append(rooted, route)
	}
	routes = rooted

	var templates []templateRoute
	declaredLiterals := map[string]struct{}{}
	for _, route := range routes {
		if len(route.PathParams) > 0 && route.PathTemplate != nil {
			templates = append(templates, templateRoute{route: route, template: *route.PathTemplate})
			continue
		}
		// Only a declared literal outranks a template; an observed hit is free to fold.
		if route.Evidence != nil && *route.Evidence == DeclaredRouteEvidence {
			declaredLiterals[routeKey(route.Method, route.BaseUrl, route.Path)] = struct{}{}
		}
	}
	if len(templates) == 0 {
		return routes
	}

	folded := make([]*discover.RouteDetails, 0, len(routes))
	for _, route := range routes {
		if len(route.PathParams) > 0 && route.PathTemplate != nil {
			folded = append(folded, route)
			continue
		}

		matched := false
		for _, candidate := range templates {
			if candidate.route.Method != route.Method ||
				NormalizeBaseURLForIdentity(candidate.route.BaseUrl) != NormalizeBaseURLForIdentity(route.BaseUrl) {
				continue
			}
			values, ok := templateMatchesLiteral(candidate.template, route.Path)
			if !ok {
				continue
			}
			// Router semantics: an explicitly declared literal beats a template that also matches.
			if _, isDeclared := declaredLiterals[routeKey(route.Method, route.BaseUrl, route.Path)]; isDeclared {
				continue
			}
			for _, param := range candidate.route.PathParams {
				if value, exists := values[param.Name]; exists {
					param.ExampleValues = appendUniqueValue(param.ExampleValues, value)
				}
			}
			candidate.route.QueryParams = MergeQueryParams(candidate.route.QueryParams, route.QueryParams)
			candidate.route.BodyParams = MergeBodyParams(candidate.route.BodyParams, route.BodyParams)
			matched = true
			break
		}
		if !matched {
			folded = append(folded, route)
		}
	}

	return MergeWebRoutes(folded)
}

// routeKey builds the identity a route is deduplicated on, matching MergeWebRoutes.
func routeKey(method common.HttpMethod, baseURL string, path string) string {
	return fmt.Sprintf("%s:%s%s", method, NormalizeBaseURLForIdentity(baseURL), path)
}

// appendUniqueValue appends a value if it is not already present.
func appendUniqueValue(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// EvidenceRank orders a declaration above an interpolation above where the content was found.
func EvidenceRank(evidence *string) int {
	if evidence == nil {
		return 0
	}
	switch *evidence {
	case DeclaredRouteEvidence:
		return 3
	case InterpolatedRouteEvidence:
		return 2
	default:
		return 1
	}
}

// IsProvenanceEvidence reports evidence recording how a route was derived, not where it was found.
func IsProvenanceEvidence(evidence string) bool {
	return EvidenceRank(&evidence) >= 2
}

// IsTemplatedPath reports a declaration rather than a URL that can be requested.
func IsTemplatedPath(path string) bool {
	return strings.Contains(path, "{") && strings.Contains(path, "}")
}

// MergePathParams merges two slices of RoutePathParam, retaining unique params and merging example values.
func MergePathParams(params1 []*discover.RoutePathParam, params2 []*discover.RoutePathParam) []*discover.RoutePathParam {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discover.RoutePathParam)
	order := make([]string, 0, len(params1)+len(params2))
	for _, param := range params1 {
		if _, exists := paramMap[param.Name]; !exists {
			order = append(order, param.Name)
		}
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		existingParam, exists := paramMap[param.Name]
		if !exists {
			paramMap[param.Name] = param
			order = append(order, param.Name)
			continue
		}
		if existingParam.ExampleValues != nil && param.ExampleValues != nil {
			// Use a set to deduplicate example values
			valueSet := make(map[string]struct{})
			for _, val := range existingParam.ExampleValues {
				valueSet[val] = struct{}{}
			}
			deduplicatedValues := existingParam.ExampleValues
			for _, val := range param.ExampleValues {
				if _, seen := valueSet[val]; seen {
					continue
				}
				valueSet[val] = struct{}{}
				deduplicatedValues = append(deduplicatedValues, val)
			}
			existingParam.ExampleValues = deduplicatedValues
		} else if param.ExampleValues != nil {
			existingParam.ExampleValues = param.ExampleValues
		} // else existingParam.ExampleValues is already set
		paramMap[param.Name] = existingParam
	}

	// Path parameters are positional, so preserve insertion order rather than ranging the map.
	mergedParams := make([]*discover.RoutePathParam, 0, len(order))
	for _, name := range order {
		mergedParams = append(mergedParams, paramMap[name])
	}
	return mergedParams
}

// InterpolatedRouteEvidence marks a route whose parameter is proven but only loosely named.
const InterpolatedRouteEvidence = "interpolated"

// wrapperCallArgumentPattern unwraps a call with one identifier argument, e.g. encodeURIComponent(id).
var wrapperCallArgumentPattern = regexp.MustCompile(`^[A-Za-z_$][\w$.]*\(\s*([A-Za-z_$][\w$.]*)\s*\)$`)

var identifierExpressionPattern = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$`)

var trailingWordPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*)[^A-Za-z0-9]*$`)

// singularize strips a naive English plural suffix.
func singularize(word string) string {
	switch {
	case strings.HasSuffix(word, "ies") && len(word) > 3:
		return word[:len(word)-3] + "y"
	case strings.HasSuffix(word, "sses"), strings.HasSuffix(word, "shes"), strings.HasSuffix(word, "ches"):
		return word[:len(word)-2]
	case strings.HasSuffix(word, "ss"):
		return word
	case strings.HasSuffix(word, "s") && len(word) > 1:
		return word[:len(word)-1]
	}
	return word
}

// trailingWord returns the last alphabetic word in a fragment, or "" when there is none.
func trailingWord(fragment string) string {
	match := trailingWordPattern.FindStringSubmatch(fragment)
	if match == nil {
		return ""
	}
	return match[1]
}

// InterpolatedParamName derives a name; unlike a declaration it is a best effort, not authoritative.
//
// The preceding path segment is deliberately not used. It is as often a verb or a generic token as
// a resource, which produced names like lockId and idId, and it varies with the call site so one
// route family fragments into differently named duplicates. A positional name is stable and does
// not claim a meaning the bundle never carried.
func InterpolatedParamName(expression string, segmentPrefix string, segmentIndex int) string {
	if unwrapped := wrapperCallArgumentPattern.FindStringSubmatch(expression); unwrapped != nil {
		expression = unwrapped[1]
	}
	if identifierExpressionPattern.MatchString(expression) {
		parts := strings.Split(expression, ".")
		last := parts[len(parts)-1]
		// Minified locals carry no meaning.
		if len(last) >= 3 && !strings.EqualFold(last, "this") {
			return last
		}
	}
	if word := trailingWord(segmentPrefix); word != "" {
		return singularize(word) + "Id"
	}
	return fmt.Sprintf("param%d", segmentIndex)
}

// Names must be unique per route: the ontology keys on (parameter_name, parameter_location).
func UniqueParamName(name string, taken map[string]struct{}) string {
	candidate := name
	for suffix := 2; ; suffix++ {
		if _, exists := taken[candidate]; !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s%d", name, suffix)
	}
}
