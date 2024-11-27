package apiapplication

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type SwaggerLibrary struct{}

func (swaggerLib *SwaggerLibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	// Initialize structs
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleSwagger),
		Timestamp: time.Now(),
	}
	errors := []string{}

	// Common Swagger paths to check
	swaggerPaths := []string{
		"/swagger-ui-bundle.js",
		"/swagger-ui.html",
		"/swagger/index.html",
		"/swagger",
		"/api-docs",
		"/v2/api-docs",
		"/swagger/v1/swagger.json",
		"/api/swagger",
		"/swagger.json",
		"/swagger.yaml",
	}

	// Create HTTP client with TLS skip verify
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, path := range swaggerPaths {
		request := webscan.DetectRequestInfo{
			BaseUrl: target,
			Path:    path,
			Method:  webscan.HttpMethodGet,
		}

		fullURL := strings.TrimSuffix(target, "/") + path
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		req.Header.Set("Accept", "text/html")

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

		// If we detect Swagger, mark as found and continue checking other endpoints
		if swaggerLib.AnalyzeResponse(responseInfo) {
			attempt.Finding = true
		}
	}

	return &attempt, errors
}

func (swaggerLib *SwaggerLibrary) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	// Validate response
	if response == nil || response.StatusCode == nil || response.ResponseBody == nil || response.ResponseHeaders == nil {
		return false
	}

	// Ensure the status code is 200 (OK)
	if *response.StatusCode != 200 {
		return false
	}

	// Check response body for Swagger indicators
	swaggerIndicators := []string{
		"swagger:", "<div id=\"swagger-ui\">", "\"openapi\":",
		"\"paths\":", "\"components\":", "\"info\": {\"title\":",
		"Swagger UI", "loadSwaggerUI", "\"swagger\":",
	}
	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range swaggerIndicators {
		if strings.Contains(body, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check response headers for Swagger-related headers
	swaggerHeaders := []string{"x-swagger-router-basepath", "x-swagger-router-controller"}
	for header := range response.ResponseHeaders {
		headerLower := strings.ToLower(header)
		for _, swaggerHeader := range swaggerHeaders {
			if headerLower == strings.ToLower(swaggerHeader) {
				return true
			}
		}
	}

	return false
}
