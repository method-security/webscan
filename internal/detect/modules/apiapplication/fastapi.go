package apiapplication

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type FastAPILibrary struct{}

func (fastapiLib *FastAPILibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	// Initialize structs
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleFastapi),
		Timestamp: time.Now(),
	}
	errors := []string{}

	// FastAPI paths to check
	fastapiPaths := []string{
		"/docs",
		"/redoc",
		"/openapi.json",
	}

	// Create HTTP client with TLS skip verify
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, path := range fastapiPaths {
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

		// If we detect FastAPI, mark as found and continue checking other endpoints
		if fastapiLib.AnalyzeResponse(responseInfo) {
			attempt.Finding = true
		}
	}

	return &attempt, errors
}

func (fastapiLib *FastAPILibrary) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	// Ensure the response and its body are valid
	if response == nil || response.ResponseBody == nil || response.ResponseHeaders == nil {
		return false
	}

	// Indicators to identify FastAPI responses in the body
	bodyIndicators := []string{
		"FastAPI - Swagger UI",
		"FastAPI - ReDoc",
		"fastapi.tiangolo.com",
	}

	// Headers that may indicate a FastAPI response
	headerIndicators := map[string]string{
		"x-process-time": "", // FastAPI default header
	}

	// Check body for FastAPI-specific indicators
	body := *response.ResponseBody
	for _, indicator := range bodyIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	// Check headers for FastAPI-specific indicators
	for key, expectedValue := range headerIndicators {
		if value, exists := response.ResponseHeaders[key]; exists {
			if expectedValue == "" || strings.Contains(value, expectedValue) {
				return true
			}
		}
	}

	return false
}
