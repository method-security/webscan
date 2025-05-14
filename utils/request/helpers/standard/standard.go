package request

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"maps"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/valyala/fasthttp"
)

func StandardCapture(options common.RequestConfig) common.RequestInfo {
	request := common.RequestInfo{
		BaseUrl:   options.BaseUrl,
		Path:      options.Path,
		Method:    options.Method,
		Timestamp: time.Now(),
	}

	// Construct the URL
	fullURL, err := constructURL(options.BaseUrl, options.Path, options.RequestParams.PathParams, options.RequestParams.QueryParams)
	if err != nil {
		request.Errors = append(request.Errors, err.Error())
		return request
	}

	// Prepare request body and content type
	reqBody, contentType, err := prepareRequestBody(options.RequestParams)
	if err != nil {
		request.Errors = append(request.Errors, err.Error())
		return request
	}

	// Check for escape characters in headers
	hasEscapeChars := false
	for key, value := range options.RequestParams.HeaderParams {
		if strings.Contains(key, "\r") || strings.Contains(key, "\n") || strings.Contains(key, "\\") || strings.Contains(key, "\u0000") {
			hasEscapeChars = true
			break
		}
		if strings.Contains(value, "\r") || strings.Contains(value, "\n") || strings.Contains(value, "\\") || strings.Contains(value, "\u0000") {
			hasEscapeChars = true
			break
		}
	}

	var statusCode int
	var responseBody string
	responseHeader := make(map[string]string)
	var redirectChain []string

	// Create and send the request based on the presence of escape characters
	if !hasEscapeChars {
		resp, chain, err := sendRequest(fullURL, contentType, reqBody, options)
		if err != nil {
			request.Errors = append(request.Errors, err.Error())
			return request
		}
		redirectChain = chain
		defer func() {
			if err := resp.Body.Close(); err != nil {
				request.Errors = append(request.Errors, fmt.Sprintf("Error closing response body: %v", err))
			}
		}()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			request.Errors = append(request.Errors, fmt.Sprintf("Failed to read response body: %v", err))
			return request
		}
		statusCode = resp.StatusCode
		responseBody = string(body)
		for key, values := range resp.Header {
			if len(values) > 0 {
				responseHeader[key] = values[0]
			}
		}
	} else {
		// Use sendFastHTTPRequest if escape characters are present
		resp, chain, err := sendFastHTTPRequest(string(options.Method), fullURL.String(), responseBody, contentType, options.RequestParams.HeaderParams, options.FollowRedirects, options)
		if err != nil {
			request.Errors = append(request.Errors, err.Error())
			return request
		}
		redirectChain = chain
		statusCode = resp.StatusCode()
		responseBody = string(resp.Body())
		resp.Header.VisitAll(func(key, value []byte) {
			responseHeader[string(key)] = string(value)
		})
		fasthttp.ReleaseResponse(resp)
	}

	// Set the redirect chain in the request info
	request.RedirectChain = redirectChain

	// Populate the rest of the report
	if headers := responseHeader; headers != nil {
		request.ResponseHeaders = make(map[string]string)
		maps.Copy(request.ResponseHeaders, headers)
	}

	request.ResponseBody = &responseBody
	request.StatusCode = &statusCode

	if len(options.RequestParams.PathParams) > 0 {
		request.PathParams = options.RequestParams.PathParams
	}
	if len(options.RequestParams.QueryParams) > 0 {
		request.QueryParams = options.RequestParams.QueryParams
	}
	if len(options.RequestParams.HeaderParams) > 0 {
		request.HeaderParams = options.RequestParams.HeaderParams
	}
	if options.RequestParams.BodyParams != nil && *options.RequestParams.BodyParams != "" {
		request.BodyParams = options.RequestParams.BodyParams
	}
	if len(options.RequestParams.FormParams) > 0 {
		request.FormParams = options.RequestParams.FormParams
	}
	if len(options.RequestParams.MultipartParams) > 0 {
		request.MultipartParams = options.RequestParams.MultipartParams
	}

	return request
}

func constructURL(baseURL, path string, pathParams, queryParams map[string]string) (*url.URL, error) {
	fullURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	endpoint := path
	for key, value := range pathParams {
		endpoint = strings.TrimRight(endpoint, "/")
		endpoint = endpoint + "/"
		endpoint = strings.ReplaceAll(endpoint, fmt.Sprintf("{%s}", key), url.PathEscape(value))
	}
	fullURL.Path = endpoint

	q := fullURL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	fullURL.RawQuery = q.Encode()

	return fullURL, nil
}

func prepareRequestBody(params *common.RequestParams) (io.Reader, string, error) {
	if params == nil {
		return nil, "", nil
	}
	if params.BodyParams != nil && *params.BodyParams != "" {
		if json.Valid([]byte(*params.BodyParams)) {
			return strings.NewReader(*params.BodyParams), "application/json", nil
		}
		return bytes.NewReader([]byte(*params.BodyParams)), "text/plain", nil
	}

	if len(params.FormParams) > 0 {
		formValues := url.Values{}
		for key, value := range params.FormParams {
			formValues.Set(key, value)
		}

		encodedForm := formValues.Encode()
		return strings.NewReader(encodedForm), "application/x-www-form-urlencoded", nil
	}

	if len(params.MultipartParams) > 0 {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		for key, value := range params.MultipartParams {
			if err := writer.WriteField(key, value); err != nil {
				return nil, "", fmt.Errorf("failed to write multipart field: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			return nil, "", fmt.Errorf("failed to close multipart writer: %v", err)
		}
		return body, writer.FormDataContentType(), nil
	}

	return nil, "", nil
}

func sendRequest(fullURL *url.URL, contentType string, body io.Reader, options common.RequestConfig) (*http.Response, []string, error) {
	req, err := http.NewRequest(string(options.Method), fullURL.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range options.RequestParams.HeaderParams {
		req.Header.Add(key, value)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	redirectChain := []string{fullURL.String()}
	client := &http.Client{
		Timeout: time.Duration(options.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: options.Insecure},
		},
	}

	if options.FollowRedirects {
		// Manually follow redirects
		redirectCount := 0
		currentURL := fullURL.String()
		var lastResp *http.Response

		for redirectCount < *options.MaxRedirects {
			// Create a new request for each redirect
			req, err = http.NewRequest(string(options.Method), currentURL, body)
			if err != nil {
				return nil, redirectChain, fmt.Errorf("failed to create request: %v", err)
			}

			// Re-add headers for each request
			for key, value := range options.RequestParams.HeaderParams {
				req.Header.Add(key, value)
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}

			resp, err := client.Do(req)
			if err != nil {
				return nil, redirectChain, fmt.Errorf("failed to perform request: %v", err)
			}

			lastResp = resp
			statusCode := resp.StatusCode

			// Add current URL to chain if it's not already there
			if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != currentURL {
				redirectChain = append(redirectChain, currentURL)
			}

			// If we got a 200, we're done
			if statusCode >= 200 && statusCode < 300 {
				break
			}

			// Check if we should follow redirect
			if statusCode < 300 || statusCode >= 400 {
				break
			}

			// Get the Location header
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}

			// Resolve relative URL
			locationURL, err := resp.Request.URL.Parse(location)
			if err != nil {
				return nil, redirectChain, fmt.Errorf("failed to parse Location header: %v", err)
			}

			// Update current URL for next request
			currentURL = locationURL.String()
			redirectCount++
		}

		if lastResp == nil {
			return nil, redirectChain, fmt.Errorf("no response received")
		}

		return lastResp, redirectChain, nil
	}
	// Single request without following redirects
	resp, err := client.Do(req)
	if err != nil {
		return nil, redirectChain, fmt.Errorf("failed to perform request: %v", err)
	}
	return resp, redirectChain, nil
}

func sendFastHTTPRequest(method, urlStr string, body string, contentType string, headers map[string]string, followRedirects bool, options common.RequestConfig) (*fasthttp.Response, []string, error) {
	// Prepare the fasthttp request and response objects
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(urlStr)
	req.Header.SetMethod(method)
	req.SetBodyString(body)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	redirectChain := []string{urlStr}
	var err error
	if followRedirects {
		// Track redirects manually for FastHTTP
		maxRedirects := *options.MaxRedirects
		redirectCount := 0
		currentURL := urlStr

		for redirectCount < maxRedirects {
			req.SetRequestURI(currentURL)
			err = fasthttp.Do(req, resp)
			if err != nil {
				break
			}

			// Check for redirect
			statusCode := resp.StatusCode()

			// Add current URL to chain if it's not already there
			if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != currentURL {
				redirectChain = append(redirectChain, currentURL)
			}

			// If we got a 200, we're done
			if statusCode >= 200 && statusCode < 300 {
				break
			}

			// Check if we should follow redirect
			if statusCode < 300 || statusCode >= 400 {
				break
			}

			location := resp.Header.Peek("Location")
			if len(location) == 0 {
				break
			}

			// Handle relative URLs in Location header
			locationStr := string(location)
			locationURL, err := url.Parse(locationStr)
			if err != nil {
				break
			}

			// If the location is relative, resolve it against the current URL
			if !locationURL.IsAbs() {
				baseURL, err := url.Parse(currentURL)
				if err != nil {
					break
				}
				locationURL = baseURL.ResolveReference(locationURL)
			}

			// Add the redirect URL if it's different
			newURL := locationURL.String()
			if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != newURL {
				redirectChain = append(redirectChain, newURL)
			}
			currentURL = newURL
			redirectCount++
		}
	} else {
		err = fasthttp.Do(req, resp)
	}

	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, redirectChain, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, redirectChain, nil
}

func populateReport(report *common.RequestInfo, statusCode int, headers map[string]string, body string, params common.RequestParams, redirectChain []string) {
	if headers != nil {
		report.ResponseHeaders = make(map[string]string)
		for key, values := range headers {
			report.ResponseHeaders[key] = values
		}
	}

	report.ResponseBody = &body
	report.StatusCode = &statusCode
	report.RedirectChain = redirectChain

	if len(params.PathParams) > 0 {
		report.PathParams = params.PathParams
	}
	if len(params.QueryParams) > 0 {
		report.QueryParams = params.QueryParams
	}
	if len(params.HeaderParams) > 0 {
		report.HeaderParams = params.HeaderParams
	}
	if params.BodyParams != nil && *params.BodyParams != "" {
		report.BodyParams = params.BodyParams
	}
	if len(params.FormParams) > 0 {
		report.FormParams = params.FormParams
	}
	if len(params.MultipartParams) > 0 {
		report.MultipartParams = params.MultipartParams
	}
}

// GetHeader is a generic header helper (case‑insensitive)
func GetHeader(r *common.RequestInfo, name string) string {
	if r.ResponseHeaders == nil {
		return ""
	}
	if v, ok := r.ResponseHeaders[name]; ok {
		return v
	}
	for hn, hv := range r.ResponseHeaders {
		if strings.EqualFold(hn, name) {
			return hv
		}
	}
	return ""
}

// GetHeaderValues is a generic header helper (case‑insensitive)
func GetHeaderValues(r *common.RequestInfo, name string) []string {
	raw := GetHeader(r, name)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
