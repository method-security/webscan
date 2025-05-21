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
	"net/url"
	"strings"

	// Generated
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
)

// PerformAppEnumerateGraphQL performs a GraphQL scan against a target URL and returns the report.
func PerformAppEnumerateGraphQL(ctx context.Context, target string) enumerateapiapplicationfern.EnumerateApiApplicationRoutesReport {
	report := enumerateapiapplicationfern.EnumerateApiApplicationRoutesReport{Target: target, AppType: enumerateapiapplicationfern.ApiTypeGraphQl}

	basePath, baseEndpointURL := extractBasePathAndEndpoint(target)
	report.BaseEndpointUrl = baseEndpointURL

	addTopLevelRoute(&report, basePath)

	body, err := fetchGraphQLSchema(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	report.Raw = base64.StdEncoding.EncodeToString(body)

	var schema enumerateapiapplicationfern.GraphQlSchema
	if err := json.Unmarshal(body, &schema); err != nil {
		errMsg := fmt.Errorf("failed to unmarshal schema: %v", err)
		report.Errors = append(report.Errors, errMsg.Error())
		return report
	}

	typeFields := extractTypeFields(schema)

	populateReportWithQueries(&report, schema, typeFields)

	return report
}

func extractBasePathAndEndpoint(target string) (string, string) {
	u, err := url.Parse(target)
	if err != nil {
		return "/", target // fallback if parsing fails
	}
	baseEndpoint := u.Scheme + "://" + u.Host
	basePath := u.Path
	if basePath == "" {
		basePath = "/"
	}
	return basePath, baseEndpoint
}

func addTopLevelRoute(report *enumerateapiapplicationfern.EnumerateApiApplicationRoutesReport, basePath string) {
	baseRoute := enumerateapiapplicationfern.ApiApplicationRouteDetails{
		Path:        basePath,
		QueryParams: nil,
		Security:    nil,
		Method:      "POST",
		Type:        enumerateapiapplicationfern.ApiTypeGraphQl,
		Description: "Top-level GraphQL route",
	}
	report.Routes = append(report.Routes, &baseRoute)
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
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" {
			for _, field := range t.Fields {
				typeFields[strings.ToLower(t.Name)] = append(typeFields[strings.ToLower(t.Name)], field.Name)
			}
		}
	}
	return typeFields
}

func populateReportWithQueries(report *enumerateapiapplicationfern.EnumerateApiApplicationRoutesReport, schema enumerateapiapplicationfern.GraphQlSchema, typeFields map[string][]string) {
	for _, t := range schema.Data.Schema.Types {
		if t.Kind == "OBJECT" && (t.Name == "Query" || t.Name == "Mutation" || t.Name == "Subscription") {
			for _, field := range t.Fields {
				query := enumerateapiapplicationfern.GraphQlQuery{
					Type:   field.Name,
					Fields: typeFields[strings.ToLower(field.Name)],
				}
				report.Queries = append(report.Queries, &query)
			}
		}
	}
}
