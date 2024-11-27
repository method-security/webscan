package apiapplication

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type GraphQLLibrary struct{}

func (graphqlLib *GraphQLLibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	// Initialize structs
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGraphql),
		Timestamp: time.Now(),
	}
	errors := []string{}

	// Common GraphQL paths to check
	graphqlPaths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/graphql/v1",
		"/query",
		"/api",
	}

	// Create HTTP client with TLS skip verify
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// GraphQL introspection query
	introspectionQuery := map[string]string{
		"query": "{ __schema { queryType { name } } }",
	}
	jsonQuery, _ := json.Marshal(introspectionQuery)
	bodyStr := string(jsonQuery)

	for _, path := range graphqlPaths {
		request := webscan.DetectRequestInfo{
			BaseUrl:    target,
			Path:       path,
			Method:     webscan.HttpMethodPost,
			BodyParams: &bodyStr,
		}

		fullURL := strings.TrimSuffix(target, "/") + path
		req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonQuery))
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request, Errors: []string{err.Error()}})
			continue
		}

		// Read response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request, Errors: []string{err.Error()}})
			continue
		}

		// Convert body to string
		bodyStr := string(body)
		err = resp.Body.Close()
		if err != nil {
			attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request, Errors: []string{err.Error()}})
			continue
		}

		// Create response info
		headers := make(map[string]string)
		for key, values := range resp.Header {
			headers[key] = values[0]
		}

		statusCode := resp.StatusCode
		responseInfo := &webscan.DetectResponseInfo{
			StatusCode:      &statusCode,
			ResponseHeaders: headers,
			ResponseBody:    &bodyStr,
		}

		attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request, Response: responseInfo})

		// If we detect GraphQL, mark as found and continue checking other endpoints
		if graphqlLib.AnalyzeResponse(responseInfo) {
			attempt.Finding = true
		}
	}

	return &attempt, errors
}

func (graphqlLib *GraphQLLibrary) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	if response == nil {
		return false
	}

	// Check response body for GraphQL indicators
	if response.ResponseBody != nil {
		graphqlIndicators := []string{
			"__schema",
			"queryType",
		}

		// Check for JSON response
		var jsonResponse map[string]interface{}
		if err := json.Unmarshal([]byte(*response.ResponseBody), &jsonResponse); err == nil {
			// Check for GraphQL-specific fields in the JSON response
			for _, indicator := range graphqlIndicators {
				if strings.Contains(*response.ResponseBody, indicator) {
					return true
				}
			}
		}
	}

	return false
}
