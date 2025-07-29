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
	result := enumerateapiapplicationfern.EnumerateGraphqlResult{
		BaseEndpointUrl: target,
		ApiType:         enumerateapiapplicationfern.ApiTypeGraphQl,
	}
	report := enumerateapiapplicationfern.EnumerateGraphqlReport{Config: &enumerateapiapplicationfern.EnumerateGraphqlConfig{Target: target}, Result: &result}

	result.BaseEndpointUrl = target

	body, err := fetchGraphQLSchema(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	result.Raw = base64.StdEncoding.EncodeToString(body)

	var schema enumerateapiapplicationfern.GraphQlSchema
	if err := json.Unmarshal(body, &schema); err != nil {
		errMsg := fmt.Errorf("failed to unmarshal schema: %v", err)
		report.Errors = append(report.Errors, errMsg.Error())
		return report
	}

	typeFields := extractTypeFields(schema)

	populateReportWithQueries(&result, schema, typeFields)

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
	return body, nil
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
