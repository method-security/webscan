package apiapplication

import (
	// Standard
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	// Generated
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
)

// PerformAppEnumerateGraphQL performs a GraphQL scan against a target URL and returns the report.
func PerformAppEnumerateGraphQL(ctx context.Context, target string) enumerateapiapplicationfern.EnumerateGraphqlReport {
	report := enumerateapiapplicationfern.EnumerateGraphqlReport{Config: &enumerateapiapplicationfern.EnumerateGraphqlConfig{Target: target}}
	report.Result = &enumerateapiapplicationfern.EnumerateGraphqlResult{}

	body, err := fetchGraphQLSchema(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
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

	// Set result data after all functions succeed
	report.Result.BaseEndpointUrl = target
	report.Result.ApiType = enumerateapiapplicationfern.ApiTypeGraphQl
	report.Result.Raw = base64.StdEncoding.EncodeToString(body)

	typeFields := extractTypeFields(schema)

	populateReportWithQueries(report.Result, schema, typeFields)

	return report
}

func fetchGraphQLSchema(target string) ([]byte, error) {
	query := `{"query":"{ __schema { types { name kind description fields { name } } } }"}`
	resp, err := http.Post(target, "application/json", bytes.NewBuffer([]byte(query)))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GraphQL schema: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Println("Error closing response body:", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the response looks like HTML instead of JSON
	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "<") {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (status: %d). This may not be a GraphQL endpoint or it may be at a different path (try /graphql, /api/graphql, /v1/graphql, etc.)", resp.StatusCode)
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

func populateReportWithQueries(report *enumerateapiapplicationfern.EnumerateGraphqlResult, schema enumerateapiapplicationfern.GraphQlSchema, typeFields map[string][]string) {
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
					report.Queries = append(report.Queries, &query)
				}
			}
		}
	}
}
