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

// getRequestURL extracts the original request URL from a ResultEvent.
// Uses the path from the raw HTTP request if available, as ev.URL may not
// contain the tested path.
func getRequestURL(ev *nout.ResultEvent) string {
	parsedURL, err := url.Parse(ev.URL)
	if err != nil {
		return ev.URL
	}

	if ev.Request != "" {
		_, requestPath, _, _ := parseRawRequest(ev.Request)
		if requestPath != "" && strings.HasPrefix(requestPath, "/") {
			if idx := strings.IndexByte(requestPath, '#'); idx != -1 {
				requestPath = requestPath[:idx]
			}
			parsedURL.RawQuery = ""
			if idx := strings.IndexByte(requestPath, '?'); idx != -1 {
				parsedURL.RawQuery = requestPath[idx+1:]
				requestPath = requestPath[:idx]
			}
			if decodedPath, err := url.PathUnescape(requestPath); err == nil {
				parsedURL.Path = decodedPath
			} else {
				parsedURL.Path = requestPath
			}
		}
	}

	parsedURL.Fragment = ""
	parsedURL.RawFragment = ""
	return parsedURL.String()
}

// getTargetURL extracts the target URL from a ResultEvent for report bucketing.
// Query parameters and fragments are excluded.
func getTargetURL(ev *nout.ResultEvent) string {
	requestURL := getRequestURL(ev)
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return requestURL
	}
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	parsedURL.RawFragment = ""
	return parsedURL.String()
}

// getMatchedURL returns the final URL that Nuclei matched after redirects.
// Nuclei keeps ev.URL anchored on the original input host and stores the final
// landed URL in ev.Matched for HTTP findings.
func getMatchedURL(ev *nout.ResultEvent) string {
	if ev.Matched != "" {
		parsedURL, err := url.Parse(ev.Matched)
		if err == nil && parsedURL.Hostname() != "" {
			parsedURL.Fragment = ""
			parsedURL.RawFragment = ""
			return parsedURL.String()
		}
	}
	return getRequestURL(ev)
}

func getNucleiNormalizedRequestURL(ev *nout.ResultEvent) string {
	parsedURL, err := url.Parse(ev.URL)
	if err != nil {
		return ev.URL
	}

	if ev.Request != "" {
		_, requestPath, _, _ := parseRawRequest(ev.Request)
		if requestPath != "" && strings.HasPrefix(requestPath, "/") {
			if parsedRequestPath, err := url.Parse(requestPath); err == nil {
				if decodedPath, err := url.PathUnescape(parsedRequestPath.Path); err == nil {
					parsedURL.Path = decodedPath
				} else {
					parsedURL.Path = parsedRequestPath.Path
				}
				parsedURL.RawPath = parsedRequestPath.Path
				parsedURL.RawQuery = parsedRequestPath.RawQuery
			}
		}
	}

	parsedURL.Fragment = ""
	parsedURL.RawFragment = ""
	return parsedURL.String()
}

func urlsEqual(firstURL, secondURL string) bool {
	if firstURL == secondURL {
		return true
	}

	firstParsed, firstErr := url.Parse(firstURL)
	secondParsed, secondErr := url.Parse(secondURL)
	if firstErr != nil || secondErr != nil {
		return false
	}
	if firstParsed.Path == "" {
		firstParsed.Path = "/"
	}
	if secondParsed.Path == "" {
		secondParsed.Path = "/"
	}
	return firstParsed.String() == secondParsed.String()
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

	// Marshal Request Struct from the original input URL.
	requestURL, err := url.Parse(ev.URL)
	if err != nil {
		// If we can't parse the URL, still include what we can
		request.BaseUrl = ev.URL
		request.Path = "/"
	} else {
		request.BaseUrl = fmt.Sprintf("%s://%s", requestURL.Scheme, requestURL.Host)
		request.Path = requestURL.Path
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

	// Parse query parameters - prefer raw request query string, fall back to the input URL.
	queryStringToParse := rawRequestQueryString
	if queryStringToParse == "" && requestURL != nil && requestURL.RawQuery != "" {
		queryStringToParse = requestURL.RawQuery
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

	// Nuclei does not expose the full redirect hop list, but it does expose the
	// original target and final landed URL.
	var redirectChain []string
	originalURL := getRequestURL(ev)
	if originalURL != "" {
		redirectChain = append(redirectChain, originalURL)
	}
	if matchedURL := getMatchedURL(ev); matchedURL != "" && !urlsEqual(matchedURL, originalURL) && !urlsEqual(matchedURL, getNucleiNormalizedRequestURL(ev)) {
		redirectChain = append(redirectChain, matchedURL)
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
