package enumeratejavascript

import (
	// Standard
	"regexp"
	"sort"
	"strings"
)

var (
	chunkParamPattern     = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*=>`)
	publicPathPattern     = regexp.MustCompile(`[A-Za-z_$][\w$]*\.p\s*=\s*"([^"]*)"`)
	hashEntryPattern      = regexp.MustCompile(`(?:"?([A-Za-z0-9_-]+)"?)\s*:\s*"([A-Za-z0-9_-]+)"`)
	viteAssetPattern      = regexp.MustCompile(`["']((?:\./|/)?(?:[A-Za-z0-9_\-./]*/)?assets/[A-Za-z0-9_\-.]+\.js)["']`)
	renameTernaryTemplate = `(\d+)\s*===\s*%s\s*\?\s*"([^"]*)"\s*:\s*%s`
)

// chunkExpression is the parsed form of webpack's `__webpack_require__.u` chunk-name builder.
type chunkExpression struct {
	parts   []chunkPart
	hashes  map[string]string
	renames map[string]string
}

type chunkPartKind int

const (
	partLiteral chunkPartKind = iota
	partChunkID
	partHashLookup
)

type chunkPart struct {
	kind chunkPartKind
	text string
}

// ExtractPublicPath returns the webpack publicPath a runtime bundle configures, if any.
func ExtractPublicPath(content string) string {
	match := publicPathPattern.FindStringSubmatch(content)
	if match == nil {
		return ""
	}
	return match[1]
}

// ExtractWebpackChunkNames returns the file name webpack builds for every chunk its runtime declares.
func ExtractWebpackChunkNames(content string) []string {
	expression, ok := parseChunkExpression(content)
	if !ok {
		return nil
	}

	ids := make([]string, 0, len(expression.hashes))
	for id := range expression.hashes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if name := expression.build(id); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// ExtractViteChunkNames returns asset-directory JavaScript paths referenced as string literals.
func ExtractViteChunkNames(content string) []string {
	seen := map[string]struct{}{}
	for _, match := range viteAssetPattern.FindAllStringSubmatch(content, -1) {
		seen[strings.TrimPrefix(match[1], "./")] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// build renders the chunk file name for one chunk id.
func (e *chunkExpression) build(id string) string {
	var out strings.Builder
	for _, part := range e.parts {
		switch part.kind {
		case partLiteral:
			out.WriteString(part.text)
		case partChunkID:
			if renamed, ok := e.renames[id]; ok {
				out.WriteString(renamed)
				continue
			}
			out.WriteString(id)
		case partHashLookup:
			hash, ok := e.hashes[id]
			if !ok {
				return ""
			}
			out.WriteString(hash)
		}
	}
	return out.String()
}

// parseChunkExpression locates `.u=<param>=>...` and decomposes its concatenation into parts.
func parseChunkExpression(content string) (*chunkExpression, bool) {
	for _, start := range assignmentOffsets(content, ".u") {
		body := content[start:]
		paramMatch := chunkParamPattern.FindStringSubmatch(body)
		if paramMatch == nil {
			continue
		}
		param := paramMatch[1]
		body = body[len(paramMatch[0]):]

		expressionText := body[:expressionEnd(body)]
		expression := &chunkExpression{
			hashes:  map[string]string{},
			renames: map[string]string{},
		}

		renamePattern, err := regexp.Compile(strings.ReplaceAll(renameTernaryTemplate, "%s", regexp.QuoteMeta(param)))
		if err != nil {
			continue
		}
		for _, match := range renamePattern.FindAllStringSubmatch(expressionText, -1) {
			expression.renames[match[1]] = match[2]
		}

		if !expression.decompose(expressionText, param) || len(expression.hashes) == 0 {
			continue
		}
		return expression, true
	}
	return nil, false
}

// decompose splits the concatenation into literal, chunk-id and hash-lookup parts.
func (e *chunkExpression) decompose(expression string, param string) bool {
	for _, operand := range splitTopLevel(expression, '+') {
		operand = strings.TrimSpace(operand)
		if operand == "" {
			continue
		}

		if literal, ok := stringLiteral(operand); ok {
			e.parts = append(e.parts, chunkPart{kind: partLiteral, text: literal})
			continue
		}
		if operand == param || strings.Contains(operand, "==="+param) || strings.Contains(operand, "==="+param+"?") {
			e.parts = append(e.parts, chunkPart{kind: partChunkID})
			continue
		}
		if strings.HasPrefix(operand, "{") && strings.HasSuffix(operand, "["+param+"]") {
			for _, entry := range hashEntryPattern.FindAllStringSubmatch(operand, -1) {
				e.hashes[entry[1]] = entry[2]
			}
			e.parts = append(e.parts, chunkPart{kind: partHashLookup})
			continue
		}
		return false
	}
	return len(e.parts) > 0
}

// assignmentOffsets returns the offsets just past each `<suffix>=` assignment in content.
func assignmentOffsets(content string, suffix string) []int {
	var offsets []int
	needle := suffix + "="
	for index := 0; ; {
		found := strings.Index(content[index:], needle)
		if found < 0 {
			return offsets
		}
		absolute := index + found + len(needle)
		// `.u==` is a comparison, not the chunk-name assignment.
		if absolute < len(content) && content[absolute] != '=' {
			offsets = append(offsets, absolute)
		}
		index = absolute
	}
}

// expressionEnd returns the length of the assignment body, stopping at the first top-level comma.
func expressionEnd(body string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(body); i++ {
		c := body[i]
		if quote != 0 {
			switch {
			case c == '\\':
				i++
			case c == quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return len(body)
}

// splitTopLevel splits on a separator that is outside every bracket and string.
func splitTopLevel(expression string, separator byte) []string {
	var parts []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expression); i++ {
		c := expression[i]
		if quote != 0 {
			switch {
			case c == '\\':
				i++
			case c == quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case separator:
			if depth == 0 {
				parts = append(parts, expression[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, expression[start:])
}

// stringLiteral unwraps a quoted operand, reporting whether the operand was one.
func stringLiteral(operand string) (string, bool) {
	if len(operand) < 2 {
		return "", false
	}
	quote := operand[0]
	if quote != '"' && quote != '\'' && quote != '`' {
		return "", false
	}
	if operand[len(operand)-1] != quote {
		return "", false
	}
	return operand[1 : len(operand)-1], true
}
