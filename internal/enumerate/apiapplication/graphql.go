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

	// Generated
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// PerformAppEnumerateGraphQL performs a GraphQL scan against a target URL and returns the report.
func PerformAppEnumerateGraphQL(ctx context.Context, target string) enumerateapiapplicationfern.EnumerateGraphqlReport {
	log := svc1log.FromContext(ctx)
	log.Info("Performing GraphQL scan", svc1log.SafeParam("target", target))

	report := enumerateapiapplicationfern.EnumerateGraphqlReport{Config: &enumerateapiapplicationfern.EnumerateGraphqlConfig{Target: target}}
	report.Result = &enumerateapiapplicationfern.EnumerateGraphqlResult{}
	data := &enumerateapiapplicationfern.EnumerateGraphqlData{}

	body, err := fetchGraphQLSchema(ctx, target)
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

	// Set data after all functions succeed
	data.BaseEndpointUrl = target
	data.ApiType = enumerateapiapplicationfern.ApiTypeGraphQl
	data.Raw = base64.StdEncoding.EncodeToString(body)

	typeFields := extractTypeFields(schema)

	populateReportWithQueries(data, schema, typeFields)

	// Marshal Report data
	report.Result.Data = data
	return report
}

func fetchGraphQLSchema(ctx context.Context, target string) ([]byte, error) {
	log := svc1log.FromContext(ctx)

	query := `{"query":"{ __schema { types { name kind description fields { name } } } }"}`
	resp, err := http.Post(target, "application/json", bytes.NewBuffer([]byte(query)))
	if err != nil {
		log.Error("Failed to fetch GraphQL schema", svc1log.SafeParam("error", err))
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
