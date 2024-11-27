package apiapplication

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type FastAPILibrary struct{}

func (fastapiLib *FastAPILibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttempt, []string) {
	attempt := webscan.AppFingerprintAttempt{
		Name:      webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleFastapi),
		Timestamp: time.Now(),
	}
	errors := []string{}

	// Parse target URL to separate base URL and path
	parsedURL, err := url.Parse(target)
	baseURL := strings.TrimSuffix(target, "/")
	targetPath := "/"
	if err == nil && parsedURL.Path != "" {
		baseURL = parsedURL.Scheme + "://" + parsedURL.Host
		targetPath = parsedURL.Path
	}

	// Common FastAPI paths to check
	fastapiPaths := []string{
		"/docs",
		"/redoc",
		"/openapi.json",
	}

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, path := range fastapiPaths {
		request := webscan.AppFingerprintRequestInfo{
			BaseUrl: baseURL,
			Path:    strings.TrimSuffix(targetPath, "/") + path,
			Method:  webscan.HttpMethodGet,
		}

		fullURL := baseURL + strings.TrimSuffix(targetPath, "/") + path
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.AppFingerprintAttemptInfo{Request: &request, Errors: []string{err.Error()}})
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.AppFingerprintAttemptInfo{Request: &request, Errors: []string{err.Error()}})
			continue
		}

		bodyStr := string(body)
		err = resp.Body.Close()
		if err != nil {
			attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.AppFingerprintAttemptInfo{Request: &request, Errors: []string{err.Error()}})
			continue
		}

		headers := make(map[string]string)
		for key, values := range resp.Header {
			headers[key] = values[0]
		}

		statusCode := resp.StatusCode
		responseInfo := &webscan.AppFingerprintResponseInfo{
			StatusCode:      &statusCode,
			ResponseHeaders: headers,
			ResponseBody:    &bodyStr,
		}

		attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.AppFingerprintAttemptInfo{Request: &request, Response: responseInfo})

		if fastapiLib.AnalyzeResponse(responseInfo) {
			attempt.Finding = true
		}
	}

	return &attempt, errors
}

func (fastapiLib *FastAPILibrary) AnalyzeResponse(response *webscan.AppFingerprintResponseInfo) bool {
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
