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

// getTargetURL extracts the target URL from a ResultEvent.
// excludes query parameters and fragment ie. https://example.com/path?query#fragment -> https://example.com/path
// Uses the path from the raw HTTP request if available, as ev.URL may not contain the tested path
func getTargetURL(ev *nout.ResultEvent) string {
	parsedURL, err := url.Parse(ev.URL)
	if err != nil {
		return ev.URL
	}

	// Extract the actual path from the raw HTTP request
	// This is necessary because ev.URL might not contain the tested path when using path fuzzing
	if ev.Request != "" {
		_, requestPath, _, _ := parseRawRequest(ev.Request)
		// Only use the parsed path if it's non-empty and looks like a valid path (starts with /)
		if requestPath != "" && strings.HasPrefix(requestPath, "/") {
			// Strip query string and fragment if present to avoid URL encoding issues
			if idx := strings.IndexAny(requestPath, "?#"); idx != -1 {
				requestPath = requestPath[:idx]
			}
			// Decode the path since it comes URL-encoded from the HTTP request
			// This prevents double-encoding when parsedURL.String() re-encodes it
			if decodedPath, err := url.PathUnescape(requestPath); err == nil {
				parsedURL.Path = decodedPath
			} else {
				parsedURL.Path = requestPath
			}
		}
	}

	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	parsedURL.RawFragment = ""
	return parsedURL.String()
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

// getHTTPRequestResponse converts a Nuclei result event into an HttpRequestResponse structure.
// It parses both request and response data, including headers, body, and parameters.
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
	// ev.URL contains the final destination URL after all redirects
	finalURL, err := url.Parse(ev.URL)
	if err != nil {
		// If we can't parse the URL, still include what we can
		request.BaseUrl = ev.URL
		request.Path = "/"
	} else {
		request.BaseUrl = fmt.Sprintf("%s://%s", finalURL.Scheme, finalURL.Host)
		request.Path = finalURL.Path
		if request.Path == "" {
			request.Path = "/"
		}
	}

	// Parse the raw request to get the actual method, path, headers, and body
	// The path from the raw request is the actual tested path, not from ev.URL
	method, requestPath, requestHeaders, body := parseRawRequest(ev.Request)

	// Extract query string from raw request path if present
	var rawRequestQueryString string
	if requestPath != "" && strings.HasPrefix(requestPath, "/") {
		// Check for query string before stripping
		if qIdx := strings.Index(requestPath, "?"); qIdx != -1 {
			// Find the end of query string (before fragment if present)
			endIdx := strings.Index(requestPath[qIdx:], "#")
			if endIdx != -1 {
				rawRequestQueryString = requestPath[qIdx+1 : qIdx+endIdx]
			} else {
				rawRequestQueryString = requestPath[qIdx+1:]
			}
		}

		// Strip query string and fragment to get clean path
		if idx := strings.IndexAny(requestPath, "?#"); idx != -1 {
			requestPath = requestPath[:idx]
		}
		// Decode the path since it comes URL-encoded from the HTTP request
		// This prevents double-encoding issues
		if decodedPath, err := url.PathUnescape(requestPath); err == nil {
			request.Path = decodedPath
		} else {
			request.Path = requestPath
		}
	}
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

	// Parse query parameters - prefer raw request query string, fall back to finalURL
	queryStringToParse := rawRequestQueryString
	if queryStringToParse == "" && finalURL != nil && finalURL.RawQuery != "" {
		queryStringToParse = finalURL.RawQuery
	}

	if queryStringToParse != "" {
		if parsedQuery, err := url.ParseQuery(queryStringToParse); err == nil {
			for k, vs := range parsedQuery {
				if len(vs) > 0 {
					params.Query[k] = vs[0]
				}
			}
		}
	}
	request.Params = params

	// Marshal Response Struct
	statusCode, responseHeaders, responseBody := parseRawResponse(ev.Response)
	if responseBody == "" {
		responseBody = ev.Response
	}

	// Create redirect chain with the final URL if it's different from base
	var redirectChain []string
	if finalURL != nil {
		redirectChain = append(redirectChain, ev.URL) // ev.URL is the final destination
	}

	response = requesthelpers.CreateHTTPResponse(statusCode, redirectChain, singleToMulti(responseHeaders), responseBody)

	// If there was an error in the response, add it to the response body
	if ev.Error != "" {
		response.ResponseBody = requesthelpers.CreateBodyFromBytes("text/plain", []byte(fmt.Sprintf("Error: %s", ev.Error)))
	}

	// Return HttpRequestResponse
	httpRequestResponse.Request = &request
	httpRequestResponse.Response = &response
	return httpRequestResponse, nil
}
