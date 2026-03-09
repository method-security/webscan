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

// SplitTargetURL splits a target URL and standardizes it into its base URL, path, and query parameter components.
func SplitTargetURL(target string) (string, string, map[string]string, error) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", "", nil, fmt.Errorf("error parsing URL: %w", err)
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

	// Parse query parameters
	var queryParams map[string]string
	if parsedURL.RawQuery != "" {
		queryParams = make(map[string]string)
		values, err := url.ParseQuery(parsedURL.RawQuery)
		if err == nil {
			for key, vals := range values {
				if len(vals) > 0 {
					queryParams[key] = vals[0] // Use first value if multiple values exist
				}
			}
		}
	}

	return baseURL, path, queryParams, nil
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
			kv := strings.SplitN(pair, "=", 2)
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
