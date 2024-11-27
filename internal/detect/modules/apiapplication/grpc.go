package apiapplication

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type GrpcLibrary struct{}

func (grpcLib *GrpcLibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	// Initialize structs
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGrpc),
		Timestamp: time.Now(),
	}
	errors := []string{}
	isGrpc := false

	// Create HTTP client with TLS skip verify
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Common gRPC health check paths
	grpcPaths := []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1alpha.Health/Check",
		"/grpc.health.v1beta.Health/Check",
		"/grpc.reflection.v1alpha.ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflectionInfo",
		"/grpc.reflection.v1beta.ServerReflectionInfo",
		"/auth.Authentication/Login",
		"/user.UserService/GetUser",
	}

	for _, path := range grpcPaths {
		request := webscan.DetectRequestInfo{
			BaseUrl: target,
			Path:    path,
			Method:  webscan.HttpMethodPost,
		}
		fullURL := strings.TrimSuffix(target, "/") + path
		req, err := http.NewRequest("POST", fullURL, strings.NewReader("{}"))
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

		// If we detect gRPC, return immediately
		if grpcLib.AnalyzeResponse(responseInfo) {
			attempt.Finding = true
		}
	}

	attempt.Finding = isGrpc
	return &attempt, errors
}

func (grpcLib *GrpcLibrary) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	if response == nil || response.ResponseHeaders == nil {
		return false
	}

	// Check for gRPC-specific headers
	for key, value := range response.ResponseHeaders {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(value)

		// Content-Type must indicate gRPC
		if keyLower == "content-type" && strings.Contains(valueLower, "application/grpc") {
			return true
		}

		// Look for gRPC-specific headers
		if keyLower == "grpc-status" || keyLower == "grpc-message" {
			return true
		}
	}

	return false
}
