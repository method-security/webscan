package apiapplication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
)

func TestPerformAppEnumerateGraphQLReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	report := PerformAppEnumerateGraphQL(context.Background(), enumerateapiapplicationfern.EnumerateGraphqlConfig{
		Target: server.URL,
	})

	if len(report.Errors) != 1 || !strings.Contains(report.Errors[0], "status 404") {
		t.Fatalf("expected a 404 report error, got %v", report.Errors)
	}
}

func TestPerformAppEnumerateGraphQLReportsGraphQLErrorEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"errors":[{"message":"internal server error"}]}`))
	}))
	defer server.Close()

	report := PerformAppEnumerateGraphQL(context.Background(), enumerateapiapplicationfern.EnumerateGraphqlConfig{
		Target: server.URL,
	})

	if len(report.Errors) != 1 || !strings.Contains(report.Errors[0], "internal server error") {
		t.Fatalf("expected a GraphQL report error, got %v", report.Errors)
	}
	if report.Result == nil || report.Result.Data == nil || report.Result.Data.Raw == "" {
		t.Fatal("expected the failed GraphQL response to remain available for review")
	}
}

func TestPerformAppEnumerateGraphQLRetainsInvalidJSONResponse(t *testing.T) {
	const responseBody = "not-json"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(responseBody))
	}))
	defer server.Close()

	query := "query { viewer { id } }"
	report := PerformAppEnumerateGraphQL(context.Background(), enumerateapiapplicationfern.EnumerateGraphqlConfig{
		Target: server.URL,
		Query:  &query,
	})

	if len(report.Errors) != 1 || !strings.Contains(report.Errors[0], "did not return valid JSON") {
		t.Fatalf("expected a JSON report error, got %v", report.Errors)
	}
	if report.Result == nil || report.Result.Data == nil || report.Result.Data.Raw == "" {
		t.Fatal("expected the invalid JSON response to remain available for review")
	}
	if report.Result.Data.QueryResponse == nil || *report.Result.Data.QueryResponse != responseBody {
		t.Fatalf("expected query response %q, got %v", responseBody, report.Result.Data.QueryResponse)
	}
}

func TestPerformAppEnumerateGraphQLAcceptsSuccessfulIntrospectionResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"__schema":{"types":[],"directives":[]}}}`))
	}))
	defer server.Close()

	report := PerformAppEnumerateGraphQL(context.Background(), enumerateapiapplicationfern.EnumerateGraphqlConfig{
		Target: server.URL,
	})

	if len(report.Errors) != 0 {
		t.Fatalf("expected a successful report, got %v", report.Errors)
	}
	if report.Result == nil || report.Result.Data == nil {
		t.Fatal("expected introspection data in the successful report")
	}
}
