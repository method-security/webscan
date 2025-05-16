package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// StandardCapture performs an HTTP request and returns detailed information including response data.
func StandardCapture(ctx context.Context, config common.RequestConfig) common.RequestInfo {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Standard request",
		svc1log.SafeParam("url", fmt.Sprintf("%s%s", config.BaseUrl, config.Path)),
		svc1log.SafeParam("followRedirects", config.FollowRedirects),
	)

	// Set Request feilds
	// Expect for Headers which is updated in the prepareRequestBody function
	request := common.RequestInfo{
		BaseUrl:         config.BaseUrl,
		Path:            config.Path,
		Method:          config.Method,
		Timestamp:       time.Now(),
		PathParams:      config.RequestParams.PathParams,
		QueryParams:     config.RequestParams.QueryParams,
		BodyParams:      config.RequestParams.BodyParams,
		FormParams:      config.RequestParams.FormParams,
		MultipartParams: config.RequestParams.MultipartParams,
	}
	reqHeaders := config.RequestParams.HeaderParams

	// Configure Full URL
	fullURL, err := constructURL(ctx, config.BaseUrl, config.Path, &config.RequestParams.PathParams, &config.RequestParams.QueryParams)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("URL construction failed: %v", err))
		return request
	}
	log.Info("Constructed URL", svc1log.SafeParam("url", fullURL.String()))

	// Configure Request Body + Content Type Headers
	reqBody, contentType, err := prepareRequestBody(log, config.RequestParams)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("Request body preparation failed: %v", err))
		return request
	}
	if contentType != nil {
		if reqHeaders == nil {
			reqHeaders = make(map[string]string)
		}
		reqHeaders["Content-Type"] = *contentType
	}
	request.HeaderParams = reqHeaders

	// Send Request
	resp, redirectChain, err := sendConfiguredRequest(log, fullURL.String(), reqHeaders, reqBody, config)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("Request failed: %v", err))
		return request
	}
	defer resp.Body.Close()

	// Read Response Body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		request.Errors = append(request.Errors, fmt.Sprintf("Failed to read response body: %v", err))
		return request
	}
	bodyStr := string(body)

	// Configure Response fields
	statusCode := resp.StatusCode
	responseHeader := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			responseHeader[k] = v[0]
		}
	}
	request.RedirectChain = redirectChain
	request.StatusCode = &statusCode
	request.ResponseHeaders = responseHeader
	request.ResponseBody = &bodyStr

	return request
}

func constructURL(ctx context.Context, baseURL, path string, pathParams, queryParams *map[string]string) (*url.URL, error) {
	log := svc1log.FromContext(ctx)
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		log.Error("Failed to parse base URL", svc1log.SafeParam("error", err))
		return nil, err
	}

	// Standardize the path
	standardizedPath := strings.TrimRight(path, "/")
	if pathParams != nil {
		for k, v := range *pathParams {
			standardizedPath = strings.ReplaceAll(standardizedPath, fmt.Sprintf("{%s}", k), url.PathEscape(v))
		}
	}
	parsedURL.Path = standardizedPath

	// Configure Query Params
	q := parsedURL.Query()
	if queryParams != nil {
		for k, v := range *queryParams {
			q.Add(k, v)
		}
	}
	parsedURL.RawQuery = q.Encode()

	return parsedURL, nil
}

func prepareRequestBody(log svc1log.Logger, params *common.RequestParams) (io.Reader, *string, error) {
	if params == nil {
		return nil, nil, nil
	}

	if params.BodyParams != nil && *params.BodyParams != "" {
		bodyStr := *params.BodyParams
		if json.Valid([]byte(bodyStr)) {
			log.Info("Valid JSON body", svc1log.SafeParam("body", bodyStr))
			contentType := "application/json"
			return strings.NewReader(bodyStr), &contentType, nil
		}
		contentType := "text/plain"
		return strings.NewReader(bodyStr), &contentType, nil
	}

	if len(params.FormParams) > 0 {
		values := url.Values{}
		for k, v := range params.FormParams {
			values.Set(k, v)
		}
		contentType := "application/x-www-form-urlencoded"
		return strings.NewReader(values.Encode()), &contentType, nil
	}

	if len(params.MultipartParams) > 0 {
		buf := &bytes.Buffer{}
		writer := multipart.NewWriter(buf)
		for k, v := range params.MultipartParams {
			if err := writer.WriteField(k, v); err != nil {
				return nil, nil, fmt.Errorf("failed to write multipart field: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			return nil, nil, fmt.Errorf("failed to close multipart writer: %v", err)
		}
		contentType := writer.FormDataContentType()
		return buf, &contentType, nil
	}

	return nil, nil, nil
}

func sendConfiguredRequest(log svc1log.Logger, url string, headers map[string]string, body io.Reader, config common.RequestConfig) (*http.Response, []string, error) {
	// Configure HTTP Client
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Set Max Redirects to 0 if FollowRedirects is false
	if !config.FollowRedirects {
		noRedirects := 0
		config.MaxRedirects = &noRedirects
	}

	// Send Request
	return sendRequest(log, client, url, headers, body, config)
}

func sendRequest(log svc1log.Logger, client *http.Client, url string, headers map[string]string, body io.Reader, config common.RequestConfig) (*http.Response, []string, error) {
	log.Info("Sending request with redirects", svc1log.SafeParam("url", url))

	// Initialize Redirect Chain
	redirectChain := []string{url}
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, redirectChain, fmt.Errorf("failed to buffer request body: %v", err)
		}
	}

	// Handle Redirects (Runs once if MaxRedirects == 0)
	currentURL := url
	for redirects := 0; redirects <= *config.MaxRedirects; redirects++ {
		var reqBody io.Reader

		// Configure Request Body
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		// Create Request (Set Method, URL, Body)
		req, err := http.NewRequest(string(config.Method), currentURL, reqBody)
		if err != nil {
			return nil, redirectChain, fmt.Errorf("failed to create request: %v", err)
		}

		// Set Headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Send Request
		resp, err := client.Do(req)
		if err != nil {
			return nil, redirectChain, fmt.Errorf("request failed: %v", err)
		}

		// Check if Response is not a redirect, return
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, redirectChain, nil
		}

		// Get Location Header (Case Insensitive)
		location := resp.Header.Get("Location")
		if location == "" {
			return resp, redirectChain, nil
		}

		// Parse Redirect Location
		nextURL, err := resp.Request.URL.Parse(location)
		resp.Body.Close()
		if err != nil {
			return nil, redirectChain, fmt.Errorf("failed to parse redirect location: %v", err)
		}

		// Update Redirect Chain + Current URL
		log.Info("Following redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
		redirectChain = append(redirectChain, nextURL.String())
		currentURL = nextURL.String()
	}

	return nil, redirectChain, fmt.Errorf("maximum redirects (%d) exceeded", *config.MaxRedirects)
}

// Utility helpers
func GetHeader(r *common.RequestInfo, name string) string {
	for k, v := range r.ResponseHeaders {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

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
