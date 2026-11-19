package enumeratejavascript

import (
	// Standard
	"sort"
	"strings"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	"github.com/BishopFox/jsluice"
)

// concatFragment is a path literal appended to a non-literal base, with the absolute bases that base resolves to.
type concatFragment struct {
	bases       map[string]struct{}
	concatUses  int
	literalUses int
}

// scopeTypes are the nodes that open a variable scope.
var scopeTypes = map[string]struct{}{
	"program": {}, "function_declaration": {}, "function_expression": {}, "function": {}, "arrow_function": {},
	"method_definition": {}, "generator_function": {}, "generator_function_declaration": {},
}

// collectConcatFragments finds `base + "/path"` concatenations and resolves each base identifier to the URLs assigned to it.
func collectConcatFragments(analyzer *jsluice.Analyzer) map[string]*concatFragment {
	root := analyzer.RootNode()
	globals := globalAssignments(root)
	fragments := map[string]*concatFragment{}

	root.QueryMulti(`(binary_expression left: (_) @left right: (string) @path) @concat`, func(result jsluice.QueryResult) {
		concat, left, path := result.Get("concat"), result.Get("left"), result.Get("path")
		if concat == nil || left == nil || path == nil || operator(concat) != "+" {
			return
		}
		fragment := path.DecodedString()
		if !strings.HasPrefix(fragment, "/") || strings.HasPrefix(fragment, "//") {
			return
		}
		if left.IsStringy() || isLocationExpression(left) {
			return
		}
		entry := fragments[fragment]
		if entry == nil {
			entry = &concatFragment{bases: map[string]struct{}{}}
			fragments[fragment] = entry
		}
		entry.concatUses++
		if left.Type() != "identifier" {
			return
		}
		for _, base := range resolveIdentifier(left, left.Content(), globals) {
			entry.bases[base] = struct{}{}
		}
	})
	if len(fragments) == 0 {
		return fragments
	}

	root.Query(`(string) @s`, func(n *jsluice.Node) {
		if entry := fragments[n.DecodedString()]; entry != nil {
			entry.literalUses++
		}
	})
	for fragment, entry := range fragments {
		if len(entry.bases) == 0 {
			entry.bases = basesForPath(fragments, fragment)
		}
	}
	return fragments
}

// basesForPath returns the bases the same path resolves to at another concatenation, ignoring the query.
func basesForPath(fragments map[string]*concatFragment, fragment string) map[string]struct{} {
	bases := map[string]struct{}{}
	path := pathWithoutQuery(fragment)
	for other, entry := range fragments {
		if pathWithoutQuery(other) != path {
			continue
		}
		for base := range entry.bases {
			bases[base] = struct{}{}
		}
	}
	return bases
}

func pathWithoutQuery(fragment string) string {
	if cut := strings.IndexAny(fragment, "?#"); cut >= 0 {
		return fragment[:cut]
	}
	return fragment
}

// sortedBases returns the resolved bases in a stable order.
func (f *concatFragment) sortedBases() []string {
	bases := make([]string, 0, len(f.bases))
	for base := range f.bases {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	return bases
}

// standalone reports a fragment that also appears outside a concatenation, where it is root-relative.
func (f *concatFragment) standalone() bool {
	return f.literalUses > f.concatUses
}

// resolveIdentifier returns the absolute URLs name is assigned in the innermost scope that declares it.
func resolveIdentifier(use *jsluice.Node, name string, globals map[string][]string) []string {
	for n := use.Parent(); n != nil && n.IsValid(); n = n.Parent() {
		if _, isScope := scopeTypes[n.Type()]; !isScope {
			continue
		}
		if n.Type() == "program" {
			return globals[name]
		}
		if declaresParameter(n, name) {
			return nil
		}
		if values, declared := scopeAssignments(n, name); declared {
			return values
		}
	}
	return globals[name]
}

// globalAssignments maps each name assigned outside a declaring function scope to the absolute URLs it is assigned.
func globalAssignments(root *jsluice.Node) map[string][]string {
	globals := map[string][]string{}
	add := func(nameNode *jsluice.Node, value *jsluice.Node) {
		if nameNode == nil || value == nil || nameNode.Type() != "identifier" {
			return
		}
		name := nameNode.Content()
		if declaredInFunctionScope(nameNode, name) {
			return
		}
		globals[name] = append(globals[name], urlLiterals(value)...)
	}
	root.QueryMulti(`(assignment_expression left: (identifier) @name right: (_) @value)`, func(result jsluice.QueryResult) {
		add(result.Get("name"), result.Get("value"))
	})
	root.QueryMulti(`(variable_declarator name: (identifier) @name value: (_) @value)`, func(result jsluice.QueryResult) {
		add(result.Get("name"), result.Get("value"))
	})
	return globals
}

// declaredInFunctionScope reports a name a function between node and the program declares.
func declaredInFunctionScope(node *jsluice.Node, name string) bool {
	for n := node.Parent(); n != nil && n.IsValid(); n = n.Parent() {
		if _, isScope := scopeTypes[n.Type()]; !isScope || n.Type() == "program" {
			continue
		}
		if declaresParameter(n, name) {
			return true
		}
		if _, declared := scopeAssignments(n, name); declared {
			return true
		}
	}
	return false
}

// scopeAssignments collects the URLs name is given by the declarations and assignments directly in a function body.
func scopeAssignments(scope *jsluice.Node, name string) ([]string, bool) {
	body := scope.ChildByFieldName("body")
	if body == nil || !body.IsValid() || body.Type() != "statement_block" {
		return nil, false
	}
	values := []string{}
	declared := false
	for _, statement := range body.NamedChildren() {
		switch statement.Type() {
		case "variable_declaration", "lexical_declaration":
			for _, declarator := range statement.NamedChildren() {
				if declarator.Type() != "variable_declarator" {
					continue
				}
				if nameNode := declarator.ChildByFieldName("name"); nameNode != nil && nameNode.Content() == name {
					declared = true
					if value := declarator.ChildByFieldName("value"); value != nil && value.IsValid() {
						values = append(values, urlLiterals(value)...)
					}
				}
			}
		case "expression_statement":
			if expression := statement.NamedChild(0); expression != nil {
				values = append(values, assignedURLs(expression, name)...)
			}
		}
	}
	return values, declared
}

// assignedURLs collects the URLs an expression statement assigns to name, looking through comma sequences.
func assignedURLs(expression *jsluice.Node, name string) []string {
	if expression == nil || !expression.IsValid() {
		return nil
	}
	switch expression.Type() {
	case "sequence_expression":
		values := []string{}
		for _, child := range expression.NamedChildren() {
			values = append(values, assignedURLs(child, name)...)
		}
		return values
	case "assignment_expression":
		left := expression.ChildByFieldName("left")
		if left != nil && left.Type() == "identifier" && left.Content() == name {
			return urlLiterals(expression.ChildByFieldName("right"))
		}
	}
	return nil
}

// declaresParameter reports a function scope that takes name as a parameter.
func declaresParameter(scope *jsluice.Node, name string) bool {
	if parameter := scope.ChildByFieldName("parameter"); parameter != nil && parameter.IsValid() {
		return parameter.Type() == "identifier" && parameter.Content() == name
	}
	parameters := scope.ChildByFieldName("parameters")
	if parameters == nil || !parameters.IsValid() {
		return false
	}
	for _, parameter := range parameters.NamedChildren() {
		if parameter.Type() == "assignment_pattern" {
			parameter = parameter.ChildByFieldName("left")
		}
		if parameter != nil && parameter.Type() == "identifier" && parameter.Content() == name {
			return true
		}
	}
	return false
}

// urlLiterals returns the absolute URLs a value can evaluate to, following conditionals and defaults.
func urlLiterals(value *jsluice.Node) []string {
	if value == nil || !value.IsValid() {
		return nil
	}
	switch value.Type() {
	case "string":
		if base, ok := absoluteBase(value.DecodedString()); ok {
			return []string{base}
		}
	case "ternary_expression":
		return append(urlLiterals(value.ChildByFieldName("consequence")), urlLiterals(value.ChildByFieldName("alternative"))...)
	case "binary_expression":
		if op := operator(value); op == "||" || op == "??" {
			return append(urlLiterals(value.ChildByFieldName("left")), urlLiterals(value.ChildByFieldName("right"))...)
		}
	case "parenthesized_expression":
		return urlLiterals(value.NamedChild(0))
	case "assignment_expression":
		return urlLiterals(value.ChildByFieldName("right"))
	}
	return nil
}

func operator(binary *jsluice.Node) string {
	if op := binary.ChildByFieldName("operator"); op != nil && op.IsValid() {
		return op.Content()
	}
	return ""
}

// isLocationExpression reports a base read from the page's own location, which keeps the path on the bundle's host.
func isLocationExpression(node *jsluice.Node) bool {
	content := strings.TrimPrefix(strings.TrimPrefix(node.Content(), "window."), "document.")
	return strings.HasPrefix(content, "location.") || strings.HasPrefix(content, "self.location.")
}

// endpointsFor converts one jsluice URL, filing a path appended to a resolved base under that base instead of the bundle's host.
func endpointsFor(found *jsluice.URL, sourceURL string, fragments map[string]*concatFragment) []*Endpoint {
	raw := strings.TrimSpace(found.URL)
	fragment := strings.TrimPrefix(raw, jsluice.ExpressionPlaceholder)
	leadingExpression := fragment != raw && strings.HasPrefix(fragment, "/")
	entry := fragments[fragment]
	if entry == nil && !leadingExpression {
		if endpoint := toEndpoint(found, sourceURL); endpoint != nil {
			return []*Endpoint{endpoint}
		}
		return nil
	}

	relative := *found
	relative.URL = fragment
	endpoint := toEndpoint(&relative, sourceURL)
	if endpoint == nil || endpoint.BaseURL != "" {
		return nil
	}

	out := []*Endpoint{}
	keepRootRelative := entry != nil && entry.standalone() && !leadingExpression
	if keepRootRelative {
		out = append(out, endpoint.Clone())
	}
	if entry == nil {
		entry = &concatFragment{bases: basesForPath(fragments, fragment)}
	}
	bases := entry.sortedBases()
	if len(bases) == 0 {
		if keepRootRelative {
			return out
		}
		endpoint.Rooted = false
		return append(out, endpoint)
	}
	for _, base := range bases {
		origin, prefix, err := splitBase(base)
		if err != nil {
			continue
		}
		rooted := endpoint.Clone()
		rooted.BaseURL = origin
		rooted.Details.Path = requesthelpers.JoinPath(prefix, endpoint.Details.Path)
		rooted.Details.PathParams = pathParams(rooted.Details.Path)
		rooted.Rooted = true
		out = append(out, rooted)
	}
	return out
}
