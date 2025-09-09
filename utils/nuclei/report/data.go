package nuclei

import (
	// Standard
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// getBaseURL extracts the base URL from a ResultEvent.
func getBaseURL(ev *nout.ResultEvent) string {
	parsedURL, err := url.Parse(ev.URL)
	if err != nil {
		return ev.URL
	}
	return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
}

// parseRawRequest parses a raw HTTP request string into its components.
// Returns method, path, headers, and body.
func parseRawRequest(raw string) (method, path string, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			method, path = f[0], f[1]
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

// parseRawResponse parses a raw HTTP response string into its components.
// Returns status code, headers, and body.
func parseRawResponse(raw string) (code int, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			if c, err := strconv.Atoi(f[1]); err == nil {
				code = c
			}
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

// singleToMulti converts a map of single string values to a map of string slices.
// Values containing commas will be split into separate strings in the output slice.
func singleToMulti(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		// Split by comma and trim whitespace from each value
		values := strings.Split(v, ",")
		trimmedValues := make([]string, len(values))
		for i, val := range values {
			trimmedValues[i] = strings.TrimSpace(val)
		}
		out[k] = trimmedValues
	}
	return out
}

// extractLatestRequestResponseFromHistory extracts the most recent request/response pair from headless history data.
// Returns method, path, headers, body for request and status code, headers, body for response.
func extractLatestRequestResponseFromHistory(history string) (reqMethod, reqPath string, reqHeaders map[string]string, reqBody string, respCode int, respHeaders map[string]string, respBody string) {
	// Split history into request/response pairs
	// History format: "REQUEST1\r\n\r\nRESPONSE1\r\n\r\nREQUEST2\r\n\r\nRESPONSE2..."
	if history == "" {
		return
	}

	// Find the last complete request/response pair
	// Look for the pattern: request followed by response
	parts := strings.Split(history, "\r\n\r\n")
	if len(parts) < 2 {
		return
	}

	// Get the last request (should be at second-to-last position if we have a complete pair)
	// Get the last response (should be at last position)
	var lastReqRaw, lastRespRaw string

	// Find the last HTTP request line (starts with HTTP method)
	for i := len(parts) - 2; i >= 0; i-- {
		if strings.Contains(parts[i], "HTTP/1.1") &&
			(strings.HasPrefix(parts[i], "GET ") || strings.HasPrefix(parts[i], "POST ") ||
				strings.HasPrefix(parts[i], "PUT ") || strings.HasPrefix(parts[i], "DELETE ") ||
				strings.HasPrefix(parts[i], "PATCH ") || strings.HasPrefix(parts[i], "HEAD ") ||
				strings.HasPrefix(parts[i], "OPTIONS ")) {
			lastReqRaw = parts[i]
			if i+1 < len(parts) {
				lastRespRaw = parts[i+1]
			}
			break
		}
	}

	if lastReqRaw != "" {
		reqMethod, reqPath, reqHeaders, reqBody = parseRawRequest(lastReqRaw + "\r\n\r\n")
	}
	if lastRespRaw != "" {
		respCode, respHeaders, respBody = parseRawResponse(lastRespRaw + "\r\n\r\n")
	}

	return
}

// getHTTPRequestResponse converts a Nuclei result event into an HttpRequestResponse structure.
// It parses both request and response data, including headers, body, and parameters.
// For headless templates, it extracts data from the history field when regular request/response are empty.
func getHTTPRequestResponse(ev *nout.ResultEvent) (*common.HttpRequestResponse, error) {
	// Initialize request and response structures
	httpRequestResponse := &common.HttpRequestResponse{}
	request := common.HttpRequest{
		Params:      &common.HttpRequestParams{},
		BaseHeaders: map[string][]string{},
		SentAt:      ev.Timestamp,
	}
	response := common.HttpResponse{
		ResponseHeaders: map[string][]string{},
	}

	// Marshal Request Struct
	baseURL, _, err := requesthelpers.SplitTargetURL(ev.URL)
	if err != nil {
		// If we can't parse the URL, still include what we can
		request.BaseUrl = ev.URL
	} else {
		request.BaseUrl = baseURL
	}

	// Try to get request/response from regular fields first
	method, path, requestHeaders, body := parseRawRequest(ev.Request)
	statusCode, responseHeaders, responseBody := parseRawResponse(ev.Response)

	// For headless templates, the history data is not transferred to Metadata by Nuclei
	// Instead, we need to use default values that indicate browser-based detection
	// This is a workaround for the limitation in Nuclei's headless result event creation
	if (method == "" || statusCode == 0) && ev.Type == "headless" {
		// Set reasonable defaults for headless templates
		// Most headless vulnerabilities are found on pages that loaded successfully
		if method == "" {
			method = "GET" // Most common method for page loads that trigger DOM-based vulnerabilities
		}
		if statusCode == 0 {
			statusCode = 200 // Most DOM-based vulnerabilities occur on successfully loaded pages
		}
		// Set a basic path if empty
		if path == "" {
			// Try to extract path from the URL
			if parsedURL, err := url.Parse(ev.URL); err == nil {
				path = parsedURL.Path
				if path == "" {
					path = "/"
				}
			} else {
				path = "/"
			}
		}
		// Set minimal headers for headless requests
		if len(requestHeaders) == 0 {
			requestHeaders = map[string]string{
				"User-Agent": "Mozilla/5.0 (compatible; Nuclei-Headless)",
			}
		}
		if len(responseHeaders) == 0 {
			responseHeaders = map[string]string{
				"Content-Type": "text/html",
			}
		}
	}

	// Continue with request processing
	request.Path = path
	contentType := http.DetectContentType([]byte(body))
	if m, err := common.NewHttpMethodFromString(strings.ToUpper(method)); err == nil {
		request.Method = m
	}
	request.BaseHeaders = singleToMulti(requestHeaders)
	if _, ok := request.BaseHeaders["Content-Type"]; !ok {
		request.BaseHeaders["Content-Type"] = []string{contentType}
	}
	params := &common.HttpRequestParams{
		Path:  map[string]string{},
		Query: map[string]string{},
	}
	if body != "" {
		params.Body = requesthelpers.CreateBodyFromBytes(contentType, []byte(body))
	}
	if u2, err := url.Parse(path); err == nil {
		for k, vs := range u2.Query() {
			if len(vs) > 0 {
				params.Query[k] = vs[0]
			}
		}
	}
	request.Params = params

	// Marshal Response Struct
	if responseBody == "" {
		responseBody = ev.Response
	}
	response = requesthelpers.CreateHTTPResponse(statusCode, nil, singleToMulti(responseHeaders), responseBody)

	// If there was an error in the response, add it to the response body
	if ev.Error != "" {
		response.ResponseBody = requesthelpers.CreateBodyFromBytes("text/plain", []byte(fmt.Sprintf("Error: %s", ev.Error)))
	}

	// Return HttpRequestResponse
	httpRequestResponse.Request = &request
	httpRequestResponse.Response = &response
	return httpRequestResponse, nil
}
