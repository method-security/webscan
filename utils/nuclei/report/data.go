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
	baseURL, _, err := requesthelpers.SplitTargetURL(ev.URL)
	if err != nil {
		// If we can't parse the URL, still include what we can
		request.BaseUrl = ev.URL
	} else {
		request.BaseUrl = baseURL
	}

	method, path, requestHeaders, body := parseRawRequest(ev.Request)
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
	statusCode, responseHeaders, responseBody := parseRawResponse(ev.Response)
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
