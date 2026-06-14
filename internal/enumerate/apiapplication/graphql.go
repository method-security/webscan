package apiapplication

import (
	// Standard
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	// Generated
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const defaultGraphQLTimeout = 30

// introspectionQuery is the standard full-depth introspection query used by GraphiQL/Apollo
// clients. It walks types via FullType -> InputValue -> TypeRef seven levels deep (the depth
// the reference Apollo client uses for production schemas), capturing args, input fields,
// interfaces, enum values, possible types, and directives.
const introspectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}`

// PerformAppEnumerateGraphQL performs a GraphQL scan against a target URL and returns the report.
// When config.Query is set, the ad-hoc query is executed and its raw response returned instead
// of running schema introspection. Mutation and subscription operations are rejected at the AST
// level unless config.AllowMutations is explicitly true.
func PerformAppEnumerateGraphQL(ctx context.Context, config enumerateapiapplicationfern.EnumerateGraphqlConfig) enumerateapiapplicationfern.EnumerateGraphqlReport {
	log := svc1log.FromContext(ctx)
	log.Info("Performing GraphQL scan", svc1log.SafeParam("target", config.Target))

	report := enumerateapiapplicationfern.EnumerateGraphqlReport{Config: &config}
	report.Result = &enumerateapiapplicationfern.EnumerateGraphqlResult{}
	data := &enumerateapiapplicationfern.EnumerateGraphqlData{}

	// AST gate: if the caller supplied an ad-hoc query, classify its operation type and reject
	// mutations and subscriptions unless explicitly allowed. The introspection query is always
	// safe (read-only), so we only gate when config.Query is set.
	if config.Query != nil && *config.Query != "" {
		allowMutations := config.AllowMutations != nil && *config.AllowMutations
		if err := validateQueryOperations(*config.Query, allowMutations); err != nil {
			report.Errors = append(report.Errors, err.Error())
			report.Result.Data = data
			return report
		}
	}

	requestBody, err := buildGraphQLRequestBody(config)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	body, err := fetchGraphQL(ctx, config.Target, requestBody, config.Headers, config.Cookies, config.Timeout)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	data.BaseEndpointUrl = config.Target
	data.ApiType = enumerateapiapplicationfern.ApiTypeGraphQl
	data.Raw = base64.StdEncoding.EncodeToString(body)

	// Ad-hoc query mode: return the raw response without introspection parsing.
	if config.Query != nil && *config.Query != "" {
		response := string(body)
		data.QueryResponse = &response
		report.Result.Data = data
		return report
	}

	// Check if the response is valid JSON
	var jsonCheck interface{}
	if err := json.Unmarshal(body, &jsonCheck); err != nil {
		errMsg := fmt.Sprintf("endpoint did not return valid JSON: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return report
	}

	var schema enumerateapiapplicationfern.GraphQlSchema
	if err := json.Unmarshal(body, &schema); err != nil {
		errMsg := fmt.Errorf("failed to unmarshal schema: %v", err)
		report.Errors = append(report.Errors, errMsg.Error())
		return report
	}

	typeFields := extractTypeFields(schema)

	populateReportWithQueries(data, schema, typeFields)
	populateReportWithDirectives(data, schema)

	// Marshal Report data
	report.Result.Data = data
	return report
}

// buildGraphQLRequestBody returns the JSON POST body. Defaults to the deep introspection
// query; when an ad-hoc query is supplied it is JSON-encoded with optional variables.
func buildGraphQLRequestBody(config enumerateapiapplicationfern.EnumerateGraphqlConfig) ([]byte, error) {
	if config.Query == nil || *config.Query == "" {
		payload := map[string]interface{}{"query": introspectionQuery}
		return json.Marshal(payload)
	}

	payload := map[string]interface{}{"query": *config.Query}
	if config.Variables != nil && *config.Variables != "" {
		var variables interface{}
		if err := json.Unmarshal([]byte(*config.Variables), &variables); err != nil {
			return nil, fmt.Errorf("failed to parse variables as JSON: %v", err)
		}
		payload["variables"] = variables
	}
	return json.Marshal(payload)
}

func fetchGraphQL(ctx context.Context, target string, requestBody []byte, headers map[string]string, cookies map[string]string, timeout *int) ([]byte, error) {
	log := svc1log.FromContext(ctx)

	effectiveTimeout := defaultGraphQLTimeout
	if timeout != nil && *timeout > 0 {
		effectiveTimeout = *timeout
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to build GraphQL request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	client := &http.Client{Timeout: time.Duration(effectiveTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Failed to fetch GraphQL response", svc1log.SafeParam("error", err))
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error("Error closing response body", svc1log.SafeParam("error", err))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the response looks like HTML instead of JSON
	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "<") {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (status: %d)", resp.StatusCode)
	}

	// Check for common non-GraphQL responses
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endpoint returned status %d: %s. Response: %s", resp.StatusCode, resp.Status, string(body[:min(len(body), 200)]))
	}

	return body, nil
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extractTypeFields(schema enumerateapiapplicationfern.GraphQlSchema) map[string][]string {
	typeFields := make(map[string][]string)
	// Add nil checks to prevent panic
	if schema.Data == nil || schema.Data.Schema == nil || schema.Data.Schema.Types == nil {
		return typeFields
	}

	for _, t := range schema.Data.Schema.Types {
		if t != nil && t.Kind == "OBJECT" && t.Fields != nil {
			for _, field := range t.Fields {
				if field != nil {
					typeFields[strings.ToLower(t.Name)] = append(typeFields[strings.ToLower(t.Name)], field.Name)
				}
			}
		}
	}
	return typeFields
}

func populateReportWithQueries(data *enumerateapiapplicationfern.EnumerateGraphqlData, schema enumerateapiapplicationfern.GraphQlSchema, typeFields map[string][]string) {
	// Add nil checks to prevent panic
	if schema.Data == nil || schema.Data.Schema == nil || schema.Data.Schema.Types == nil {
		return
	}

	for _, t := range schema.Data.Schema.Types {
		if t != nil && t.Kind == "OBJECT" && (t.Name == "Query" || t.Name == "Mutation" || t.Name == "Subscription") && t.Fields != nil {
			for _, field := range t.Fields {
				if field != nil {
					query := enumerateapiapplicationfern.GraphQlQuery{
						Type:   field.Name,
						Fields: typeFields[strings.ToLower(field.Name)],
					}
					data.Queries = append(data.Queries, &query)
				}
			}
		}
	}
}

func populateReportWithDirectives(data *enumerateapiapplicationfern.EnumerateGraphqlData, schema enumerateapiapplicationfern.GraphQlSchema) {
	if schema.Data == nil || schema.Data.Schema == nil || schema.Data.Schema.Directives == nil {
		return
	}
	data.Directives = schema.Data.Schema.Directives
}

// validateQueryOperations performs a lightweight scan of the supplied GraphQL document and
// rejects any top-level `mutation` or `subscription` operation when allowMutations is false.
//
// The scan is intentionally not a full GraphQL parser. It tracks brace/paren/bracket depth,
// skips line comments (`#...`) and string literals (block strings and ordinary strings), and
// only inspects identifiers found at depth 0. That's enough to classify every well-formed
// GraphQL document: per the spec, operation definitions can only appear at the top level.
// Anything that fails this check (e.g., a malformed document with unbalanced braces) errors
// out conservatively rather than letting a mutation slip through.
func validateQueryOperations(query string, allowMutations bool) error {
	// Short-circuit when the caller has explicitly opted in. The scanner below is
	// intentionally conservative; with --allow-mutations the operator is telling us
	// "send whatever I supplied and let the server reject it," so we skip our own
	// parsing rather than block on a malformed-but-server-acceptable document.
	if allowMutations {
		return nil
	}
	operations, err := topLevelOperationKinds(query)
	if err != nil {
		return fmt.Errorf("failed to parse query for operation gating: %v", err)
	}
	for _, op := range operations {
		if op == "mutation" || op == "subscription" {
			return fmt.Errorf(
				"rejecting %s operation: pass --allow-mutations to permit mutation or subscription operations",
				op,
			)
		}
	}
	return nil
}

// topLevelOperationKinds extracts the list of operation kinds ("query", "mutation",
// "subscription", or "anonymous" for shorthand `{...}` queries) found at depth 0 of the
// supplied document. It is a conservative scanner — it does not understand variable
// definitions, directives on operation definitions, etc., but it recognizes enough to
// identify operation keywords reliably.
func topLevelOperationKinds(query string) ([]string, error) {
	const (
		opQuery        = "query"
		opMutation     = "mutation"
		opSubscription = "subscription"
		opFragment     = "fragment"
	)

	var ops []string
	depth := 0
	i := 0
	n := len(query)

	// expectingOperation tracks whether the next identifier we see at depth 0 should be
	// classified as a top-level operation. Initially true. After we consume an operation
	// (or shorthand `{`), it stays false until we close the corresponding selection set,
	// fragment, or skip the operation body.
	for i < n {
		c := query[i]

		// Whitespace and commas (commas are syntactic whitespace in GraphQL).
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			i++
			continue
		}

		// Line comment: skip to end of line.
		if c == '#' {
			for i < n && query[i] != '\n' {
				i++
			}
			continue
		}

		// Block string `"""..."""` — skip the entire literal.
		if c == '"' && i+2 < n && query[i+1] == '"' && query[i+2] == '"' {
			i += 3
			for i+2 < n {
				if query[i] == '"' && query[i+1] == '"' && query[i+2] == '"' {
					i += 3
					break
				}
				// Block strings allow `\"""` to escape the terminator.
				if query[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			continue
		}

		// Ordinary string literal.
		if c == '"' {
			i++
			for i < n && query[i] != '"' {
				if query[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if query[i] == '\n' {
					return nil, fmt.Errorf("unterminated string literal at offset %d", i)
				}
				i++
			}
			if i < n {
				i++ // consume closing quote
			}
			continue
		}

		// Braces/parens/brackets: track depth.
		if c == '{' {
			if depth == 0 {
				// Shorthand operation: anonymous query.
				ops = append(ops, "anonymous")
			}
			depth++
			i++
			continue
		}
		if c == '}' {
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced closing brace at offset %d", i)
			}
			i++
			continue
		}
		if c == '(' || c == '[' {
			depth++
			i++
			continue
		}
		if c == ')' || c == ']' {
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced closing bracket at offset %d", i)
			}
			i++
			continue
		}

		// Identifier (or keyword).
		if isIdentStart(c) {
			start := i
			for i < n && isIdentPart(query[i]) {
				i++
			}
			ident := query[start:i]
			if depth == 0 {
				switch ident {
				case opQuery, opMutation, opSubscription:
					ops = append(ops, ident)
				case opFragment:
					// Fragment definition — not an operation, but a top-level construct.
					// Don't add it to ops.
				default:
					// Some other token at depth 0 (e.g., directive name, variable). Ignore.
				}
			}
			continue
		}

		// Anything else (e.g., `@`, `$`, `=`, `!`, `:`, `.`) — just consume it.
		i++
	}

	if depth != 0 {
		return nil, fmt.Errorf("unbalanced braces in document (depth %d at end)", depth)
	}
	return ops, nil
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
