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

// FlattenHeaders converts a multi-value header map (map[string][]string) into a
// single-value header map (map[string]string) by joining multiple values with a
// comma. This is the format expected by SendHTTPRequest. Ranging over a nil map
// is safe in Go so the caller does not need to nil-check before calling.
func FlattenHeaders(headers map[string][]string) map[string]string {
	flat := make(map[string]string, len(headers))
	for k, v := range headers {
		if len(v) > 0 {
			flat[k] = strings.Join(v, ",")
		}
	}
	return flat
}

// ParseHeaderPairs converts a slice of "Name: Value" strings (as supplied via a
// repeated --header CLI flag) into a map[string]string. Each value must contain
// a colon; pairs that do not are returned as an error so the operator learns
// their header was malformed instead of having it silently dropped. Leading and
// trailing whitespace is trimmed from both the name and the value.
//
// Repeated header names are case-insensitively merged into a single comma-
// joined value per RFC 7230 §3.2.2 ("a recipient MAY combine multiple header
// fields with the same field name into one ... by appending each subsequent
// field value to the combined field value in order, separated by a comma").
// The first-seen casing of the header name is preserved. This makes repeated
// `--header "Accept: application/json"` + `--header "Accept: text/html"` emit
// `Accept: application/json, text/html` rather than dropping the second value.
//
// Returns (nil, nil) when pairs is empty.
func ParseHeaderPairs(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed --header %q: expected \"Name: Value\"", pair)
		}
		name := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if name == "" {
			return nil, fmt.Errorf("malformed --header %q: header name is empty", pair)
		}
		// Header names are case-insensitive per RFC 7230 §3.2; find any
		// existing entry that matches case-insensitively and merge into it,
		// preserving the first-seen casing.
		mergeKey := name
		for existingKey := range headers {
			if strings.EqualFold(existingKey, name) {
				mergeKey = existingKey
				break
			}
		}
		if existing, ok := headers[mergeKey]; ok && existing != "" {
			// Don't append an empty value (would leave a trailing ", ").
			if value != "" {
				headers[mergeKey] = existing + ", " + value
			}
		} else {
			headers[mergeKey] = value
		}
	}
	return headers, nil
}

// BuildAuthHeaders merges explicit request headers and cookies into a single
// multi-value header map suitable for HttpRequestParams. Cookies are folded into
// a single "Cookie" header so the standard transport forwards them; the headless
// transport additionally seeds the cookie jar from the same cookie map. Returns
// nil when neither headers nor cookies are supplied.
func BuildAuthHeaders(headers map[string]string, cookies map[string]string) map[string][]string {
	if len(headers) == 0 && len(cookies) == 0 {
		return nil
	}
	result := make(map[string][]string, len(headers)+1)
	for key, value := range headers {
		result[key] = []string{value}
	}
	if len(cookies) > 0 {
		pairs := make([]string, 0, len(cookies))
		for name, value := range cookies {
			pairs = append(pairs, fmt.Sprintf("%s=%s", name, value))
		}
		cookieValue := strings.Join(pairs, "; ")
		// Merge onto any caller-supplied Cookie header (case-insensitive) rather than
		// clobbering it, so an explicit --header "Cookie: ..." and --cookie compose.
		cookieKey := "Cookie"
		for key := range result {
			if strings.EqualFold(key, "Cookie") {
				cookieKey = key
				break
			}
		}
		if existing, ok := result[cookieKey]; ok && len(existing) > 0 && existing[0] != "" {
			result[cookieKey] = []string{existing[0] + "; " + cookieValue}
		} else {
			result[cookieKey] = []string{cookieValue}
		}
	}
	return result
}

// NormalizeHeaders trims and drops empty response header values so serialized
// header maps always conform to map<string, list<string>> without null values.
func NormalizeHeaders(headers map[string][]string) map[string][]string {
	normalized := make(map[string][]string, len(headers))
	for key, values := range headers {
		var normalizedValues []string
		for _, value := range values {
			// CDP can expose duplicate response headers as newline-delimited
			// strings. Content-Type parameters may contain commas, so only split
			// on line breaks.
			splitValues := splitHeaderValue(key, value)
			for _, v := range splitValues {
				trimmed := strings.TrimSpace(v)
				if trimmed != "" {
					normalizedValues = append(normalizedValues, trimmed)
				}
			}
		}
		if len(normalizedValues) > 0 {
			normalized[key] = normalizedValues
		}
	}
	return normalized
}

// ParseCookiePairs converts a slice of "name=value" strings (as supplied via a
// repeated --cookie CLI flag) into a map[string]string. Each value must contain
// an equals sign; pairs that do not are returned as an error so the operator
// learns their cookie was malformed instead of having it silently dropped.
// Leading and trailing whitespace is trimmed from both the name and the value.
// Returns (nil, nil) when pairs is empty.
func ParseCookiePairs(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	cookies := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed --cookie %q: expected \"name=value\"", pair)
		}
		name := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if name == "" {
			return nil, fmt.Errorf("malformed --cookie %q: cookie name is empty", pair)
		}
		cookies[name] = value
	}
	return cookies, nil
}

// ParseFormDataPairs converts a slice of "key=value" strings (as supplied via a
// repeated --form-data CLI flag) into a map[string]string. Each value must
// contain an equals sign; pairs that do not are returned as an error so the
// operator learns their value was malformed instead of having it silently
// dropped. Leading and trailing whitespace is trimmed from both the key and
// the value. Returns (nil, nil) when pairs is empty.
func ParseFormDataPairs(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	form := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed --form-data %q: expected \"key=value\"", pair)
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if key == "" {
			return nil, fmt.Errorf("malformed --form-data %q: key is empty", pair)
		}
		form[key] = value
	}
	return form, nil
}

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

func GetContentTypeFromHeaderMap(headers map[string][]string) string {
	if headers == nil {
		return ""
	}

	for headerName, values := range headers {
		if !strings.EqualFold(headerName, "Content-Type") {
			continue
		}
		for i := len(values) - 1; i >= 0; i-- {
			if value := strings.TrimSpace(values[i]); value != "" {
				return value
			}
		}
	}
	return ""
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

// DetectContentTypeFromBytes classifies body bytes using Go's content sniffing.
func DetectContentTypeFromBytes(bodyData []byte) string {
	return http.DetectContentType(bodyData)
}

// CreateBodyFromDetectedBytes classifies body bytes using Go's content sniffing.
func CreateBodyFromDetectedBytes(bodyData []byte) *common.Body {
	return CreateBodyFromBytes(DetectContentTypeFromBytes(bodyData), bodyData)
}

// IsDetectedBinaryBody reports whether body bytes classify the same way STANDARD
// would classify a binary response when no Content-Type header is available.
func IsDetectedBinaryBody(bodyData []byte) bool {
	body := CreateBodyFromDetectedBytes(bodyData)
	return body != nil && body.Kind == "binary"
}

// CreateHTTPResponseFromBytes creates an HttpResponse struct from HttpResponse data using byte array
func CreateHTTPResponseFromBytes(statusCode int, redirectChain []string, headers map[string][]string, responseBody []byte) common.HttpResponse {
	processedHeaders := NormalizeHeaders(headers)

	// Get content type from headers
	contentType := GetContentTypeFromHeaderMap(processedHeaders)

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

func splitHeaderValue(key, value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		if r == '\n' || r == '\r' {
			return true
		}
		return false
	})
}

// CreateHTTPResponse creates an HttpResponse struct from HttpResponse data (string version)
// This is a compatibility wrapper that converts string to bytes
func CreateHTTPResponse(statusCode int, redirectChain []string, headers map[string][]string, responseBody string) common.HttpResponse {
	return CreateHTTPResponseFromBytes(statusCode, redirectChain, headers, []byte(responseBody))
}
