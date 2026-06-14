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

const introspectionQuery = `{"query":"{ __schema { types { name kind description fields { name } } } }"}`

// PerformAppEnumerateGraphQL performs a GraphQL scan against a target URL and returns the report.
// When config.Query is set, the ad-hoc query is executed and its raw response returned instead
// of running schema introspection.
func PerformAppEnumerateGraphQL(ctx context.Context, config enumerateapiapplicationfern.EnumerateGraphqlConfig) enumerateapiapplicationfern.EnumerateGraphqlReport {
	log := svc1log.FromContext(ctx)
	log.Info("Performing GraphQL scan", svc1log.SafeParam("target", config.Target))

	report := enumerateapiapplicationfern.EnumerateGraphqlReport{Config: &config}
	report.Result = &enumerateapiapplicationfern.EnumerateGraphqlResult{}
	data := &enumerateapiapplicationfern.EnumerateGraphqlData{}

	requestBody, err := buildGraphQLRequestBody(config)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	body, err := fetchGraphQL(ctx, config.Target, requestBody, config.Headers, config.Timeout)
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

	// Marshal Report data
	report.Result.Data = data
	return report
}

// buildGraphQLRequestBody returns the JSON POST body. Defaults to the introspection
// query; when an ad-hoc query is supplied it is JSON-encoded with optional variables.
func buildGraphQLRequestBody(config enumerateapiapplicationfern.EnumerateGraphqlConfig) ([]byte, error) {
	if config.Query == nil || *config.Query == "" {
		return []byte(introspectionQuery), nil
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

func fetchGraphQL(ctx context.Context, target string, requestBody []byte, headers map[string]string, timeout *int) ([]byte, error) {
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
