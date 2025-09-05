package request

import (
	// Standard
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
)

// RemoveScheme removes http:// or https:// from the beginning of a string
func RemoveScheme(url string) string {
	if strings.HasPrefix(url, "http://") {
		return strings.TrimPrefix(url, "http://")
	}
	if strings.HasPrefix(url, "https://") {
		return strings.TrimPrefix(url, "https://")
	}
	return url
}

// SplitTargetURL splits a target URL and standardizes it into its base URL and path components.
func SplitTargetURL(target string) (string, string, error) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("error parsing URL: %w", err)
	}

	// Standardize the base URL (ie. http://example.com:8080/ -> http://example.com:8080)
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	baseURL = strings.TrimRight(baseURL, "/")

	// Standardize the path
	// If the path is empty or '/', set it to "", else trim the trailing slash (ie. "/foo/" -> "/foo")
	path := strings.Trim(parsedURL.Path, "/")
	if path != "" {
		path = fmt.Sprintf("/%s", path)
	}

	return baseURL, path, nil
}

// GetHeaderValueFromHeaderMap extracts a single header value from response header map.
// Returns the first value found for the given header name, or nil if not found.
func GetHeaderValueFromHeaderMap(headers map[string][]string, name string) *string {
	if headers == nil {
		return nil
	}

	for headerName, values := range headers {
		if strings.EqualFold(headerName, name) && len(values) > 0 {
			value := strings.Join(values, ", ")
			return &value
		}
	}
	return nil
}

// GetResponseBodyStringFromBodyStruct extracts string content from a Body struct
func GetResponseBodyStringFromBodyStruct(body *common.Body) *string {
	if body == nil {
		return nil
	}

	switch body.Kind {
	case "binary":
		if body.Binary != nil {
			str := body.Binary.Base64
			return &str
		}
	case "form":
		if body.Form != nil {
			var fields []string
			for k, v := range body.Form.Fields {
				fields = append(fields, k+"="+v)
			}
			str := strings.Join(fields, "&")
			return &str
		}
	case "json":
		if body.Json != nil {
			str := body.Json.Data
			return &str
		}
	case "multipart":
		if body.Multipart != nil {
			var parts []string
			for _, part := range body.Multipart.Parts {
				if part.Content != nil {
					decoded, err := base64.StdEncoding.DecodeString(part.Content.Base64)
					if err != nil {
						continue
					}
					parts = append(parts, string(decoded))
				}
			}
			str := strings.Join(parts, "")
			return &str
		}
	case "text":
		if body.Text != nil {
			str := body.Text.Value
			return &str
		}
	default:
		return nil
	}
	return nil
}

// CreateBodyFromBytes creates a Body struct based on content type and body data as bytes
func CreateBodyFromBytes(contentType string, bodyData []byte) *common.Body {
	ct := strings.TrimSpace(strings.Split(contentType, ";")[0])

	switch {
	case strings.Contains(ct, "application/json"):
		return &common.Body{
			Kind: "json",
			Json: &common.JsonBody{
				Data:     string(bodyData),
				MimeType: &ct,
			},
		}
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		fields := make(map[string]string)
		bodyStr := string(bodyData)
		for _, pair := range strings.Split(bodyStr, "&") {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				fields[kv[0]] = kv[1]
			}
		}
		return &common.Body{
			Kind: "form",
			Form: &common.FormBody{
				Fields:   fields,
				MimeType: &ct,
			},
		}
	case strings.HasPrefix(ct, "image/"),
		strings.Contains(ct, "application/octet-stream"),
		strings.Contains(ct, "application/pdf"),
		strings.Contains(ct, "application/zip"),
		strings.Contains(ct, "application/gzip"),
		strings.HasPrefix(ct, "video/"),
		strings.HasPrefix(ct, "audio/"):
		// Handle binary content types
		base64Data := base64.StdEncoding.EncodeToString(bodyData)
		return &common.Body{
			Kind: "binary",
			Binary: &common.BinaryBody{
				Base64:   base64Data,
				MimeType: &ct,
			},
		}
	default:
		return &common.Body{
			Kind: "text",
			Text: &common.TextBody{
				Value:    string(bodyData),
				MimeType: &ct,
			},
		}
	}
}

// isXSSResponse checks if the response contains XSS indicators
func isXSSResponse(responseBody []byte, headers map[string][]string) bool {
	bodyStr := strings.ToLower(string(responseBody))

	// Check for common XSS patterns in response body
	xssPatterns := []string{
		"<script>",
		"javascript:",
		"alert(",
		"onerror=",
		"onload=",
		"onclick=",
		"onfocus=",
		"onmouseover=",
		"<img src=",
		"<svg onload=",
		"<iframe src=",
		"<embed src=",
		"<object data=",
		"<form action=",
		"document.domain",
		"document.cookie",
		"xss",
	}

	// Check if response body contains XSS patterns
	for _, pattern := range xssPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	// Check if content type is HTML (XSS typically affects HTML responses)
	if ct, ok := headers["Content-Type"]; ok && len(ct) > 0 {
		contentType := strings.ToLower(ct[0])
		if strings.Contains(contentType, "text/html") {
			// Additional check for XSS-related content in HTML responses
			htmlXssPatterns := []string{
				"<script",
				"javascript:",
				"alert",
				"onerror",
				"onload",
			}
			for _, pattern := range htmlXssPatterns {
				if strings.Contains(bodyStr, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// CreateHTTPResponseFromBytes creates an HttpResponse struct from HttpResponse data using byte array
func CreateHTTPResponseFromBytes(statusCode int, redirectChain []string, headers map[string][]string, responseBody []byte) common.HttpResponse {
	// Process headers to split comma-delimited values
	processedHeaders := make(map[string][]string)
	for key, values := range headers {
		var processedValues []string
		for _, value := range values {
			// Split each value by comma and trim spaces
			splitValues := strings.Split(value, ",")
			for _, v := range splitValues {
				processedValues = append(processedValues, strings.TrimSpace(v))
			}
		}
		processedHeaders[key] = processedValues
	}

	// Get content type from headers
	contentType := ""
	if ct, ok := processedHeaders["Content-Type"]; ok && len(ct) > 0 {
		contentType = ct[0]
	}

	// If no content type is provided, try to detect it from string representation
	if contentType == "" {
		contentType = http.DetectContentType(responseBody)
	}

	// Handle XSS-related status code correction: if status code is 0 and response contains XSS indicators, set to 200
	if statusCode == 0 && isXSSResponse(responseBody, processedHeaders) {
		statusCode = 200
	}

	// Create the response body based on content type
	bodyStruct := CreateBodyFromBytes(contentType, responseBody)

	// Get current time for received timestamp
	receivedAt := time.Now()
	sizeBytes := len(responseBody)

	return common.HttpResponse{
		StatusCode:      &statusCode,
		RedirectChain:   redirectChain,
		ResponseHeaders: processedHeaders,
		ResponseBody:    bodyStruct,
		ReceivedAt:      &receivedAt,
		SizeBytes:       &sizeBytes,
	}
}

// CreateHTTPResponse creates an HttpResponse struct from HttpResponse data (string version)
// This is a compatibility wrapper that converts string to bytes
func CreateHTTPResponse(statusCode int, redirectChain []string, headers map[string][]string, responseBody string) common.HttpResponse {
	return CreateHTTPResponseFromBytes(statusCode, redirectChain, headers, []byte(responseBody))
}
