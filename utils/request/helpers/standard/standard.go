package request

import (
	// Standard
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// StandardCapture performs an HTTP request based on the provided configuration
// and returns detailed request information including response data.
func StandardCapture(ctx context.Context, config common.RequestConfig) common.RequestInfo {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Standard request", svc1log.SafeParam("url", fmt.Sprintf("%s%s", config.BaseUrl, config.Path)))
	log.Info("Redirect Config", svc1log.SafeParam("followRedirects", config.FollowRedirects))

	// Initialize the returned struct
	request := common.RequestInfo{
		BaseUrl:   config.BaseUrl,
		Path:      config.Path,
		Method:    config.Method,
		Timestamp: time.Now(),
	}
	if len(config.RequestParams.PathParams) > 0 {
		request.PathParams = config.RequestParams.PathParams
	}
	if len(config.RequestParams.QueryParams) > 0 {
		request.QueryParams = config.RequestParams.QueryParams
	}
	if len(config.RequestParams.HeaderParams) > 0 {
		request.HeaderParams = config.RequestParams.HeaderParams
	}
	if config.RequestParams.BodyParams != nil && *config.RequestParams.BodyParams != "" {
		request.BodyParams = config.RequestParams.BodyParams
	}
	if len(config.RequestParams.FormParams) > 0 {
		request.FormParams = config.RequestParams.FormParams
	}
	if len(config.RequestParams.MultipartParams) > 0 {
		request.MultipartParams = config.RequestParams.MultipartParams
	}

	// Construct the URL
	fullURL, err := constructURL(ctx, config.BaseUrl, config.Path, &config.RequestParams.PathParams, &config.RequestParams.QueryParams)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("URL construction failed: %v", err))
		return request
	}
	log.Info("Constructed URL", svc1log.SafeParam("url", fullURL.String()))

	// Prepare request body and content type
	reqBody, contentType, err := prepareRequestBody(config.RequestParams)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("Request body preparation failed: %v", err))
		return request
	}

	// Send the request and handle response
	resp, redirectChain, err := sendRequest(log, fullURL, contentType, reqBody, config)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("Request failed: %v", err))
		return request
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			request.Errors = append(request.Errors, fmt.Sprintf("Failed to close response body: %v", err))
		}
	}()

	// Process response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("Failed to read response body: %v", err))
		return request
	}

	// Populate response struct
	// Redirect chain
	request.RedirectChain = redirectChain

	// Status code
	statusCode := resp.StatusCode
	request.StatusCode = &statusCode

	// Response headers
	responseHeader := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeader[key] = values[0]
		}
	}
	request.ResponseHeaders = responseHeader

	// Response body
	responseBody := string(body)
	request.ResponseBody = &responseBody

	// Encoded response body
	encodedResponseBody := base64.StdEncoding.EncodeToString(body)
	request.EncodedResponseBody = &encodedResponseBody

	return request
}

// constructURL builds a complete URL from base URL, path, and parameters
func constructURL(ctx context.Context, baseURL, path string, pathParams, queryParams *map[string]string) (*url.URL, error) {
	log := svc1log.FromContext(ctx)
	fullURL, err := url.Parse(baseURL)
	if err != nil {
		log.Error("Failed to parse base URL", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	// Process path parameters
	endpoint := path
	if pathParams != nil {
		endpoint = strings.TrimRight(path, "/")
		for key, value := range *pathParams {
			endpoint = strings.ReplaceAll(endpoint, fmt.Sprintf("{%s}", key), url.PathEscape(value))
		}
	}
	fullURL.Path = endpoint

	// Add query parameters
	q := fullURL.Query()
	for key, value := range *queryParams {
		q.Add(key, value)
	}
	fullURL.RawQuery = q.Encode()

	return fullURL, nil
}

// prepareRequestBody prepares the request body and determines content type
func prepareRequestBody(params *common.RequestParams) (io.Reader, string, error) {
	if params == nil {
		return nil, "", nil
	}

	// Handle JSON or plain text body
	if params.BodyParams != nil && *params.BodyParams != "" {
		if json.Valid([]byte(*params.BodyParams)) {
			return strings.NewReader(*params.BodyParams), "application/json", nil
		}
		return bytes.NewReader([]byte(*params.BodyParams)), "text/plain", nil
	}

	// Handle form data
	if len(params.FormParams) > 0 {
		formValues := url.Values{}
		for key, value := range params.FormParams {
			formValues.Set(key, value)
		}
		return strings.NewReader(formValues.Encode()), "application/x-www-form-urlencoded", nil
	}

	// Handle multipart form data
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

// sendRequest performs the HTTP request and handles redirects if configured
func sendRequest(log svc1log.Logger, fullURL *url.URL, contentType string, body io.Reader, config common.RequestConfig) (*http.Response, []string, error) {
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
		},
		// Disable automatic redirect following
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// Send the request and handle redirects if configured
	if !config.FollowRedirects {
		return sendSingleRequest(log, client, fullURL.String(), contentType, body, config.RequestParams.HeaderParams)
	}
	// Handle redirects
	return handleRedirects(log, client, fullURL.String(), contentType, body, config)
}

// sendSingleRequest performs a single HTTP request without following redirects
func sendSingleRequest(log svc1log.Logger, client *http.Client, url string, contentType string, body io.Reader, headers map[string]string) (*http.Response, []string, error) {
	log.Info("Sending request", svc1log.SafeParam("url", url))
	req, err := http.NewRequest("GET", url, body)
	if err != nil {
		return nil, []string{url}, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, []string{url}, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, []string{url}, nil
}

// handleRedirects manages the redirect chain and follows redirects up to the maximum limit
func handleRedirects(log svc1log.Logger, client *http.Client, initialURL string, contentType string, body io.Reader, config common.RequestConfig) (*http.Response, []string, error) {
	log.Info("Sending redirect request", svc1log.SafeParam("url", initialURL))
	redirectCount := 0
	currentURL := initialURL
	redirectChain := []string{initialURL}

	// Buffer the original request body to reuse on redirects
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, redirectChain, fmt.Errorf("failed to buffer request body: %v", err)
		}
	}

	for redirectCount < *config.MaxRedirects {
		// Prepare a new reader for the request body
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		// Create the request
		req, err := http.NewRequest(string(config.Method), currentURL, reqBody)
		if err != nil {
			return nil, redirectChain, fmt.Errorf("failed to create request: %v", err)
		}

		// Set headers
		for key, value := range config.RequestParams.HeaderParams {
			req.Header.Set(key, value)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		// Send the request
		resp, err := client.Do(req)
		if err != nil {
			return nil, redirectChain, fmt.Errorf("failed to perform request: %v", err)
		}

		// If it's not a redirect, return the response
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, redirectChain, nil
		}

		// Get the redirect location
		location := resp.Header.Get("Location")
		if location == "" {
			// No location header, treat as final response
			return resp, redirectChain, nil
		}

		// Resolve relative location
		nextURL, err := resp.Request.URL.Parse(location)
		if err != nil {
			_ = resp.Body.Close()
			return nil, redirectChain, fmt.Errorf("failed to parse redirect location: %v", err)
		}

		// Close response body before continuing
		_ = resp.Body.Close()

		// Add the redirect URL to the chain
		redirectChain = append(redirectChain, nextURL.String())
		log.Info("Following redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))

		// Set up for next iteration
		currentURL = nextURL.String()
		redirectCount++
	}

	return nil, redirectChain, fmt.Errorf("maximum redirects (%d) exceeded", *config.MaxRedirects)
}

// GetHeader retrieves a header value case-insensitively
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

// GetHeaderValues retrieves and splits header values case-insensitively
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
