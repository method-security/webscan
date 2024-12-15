package utils

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

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/valyala/fasthttp"
)

func PerformRequestScan(baseURL, path string, method common.HttpMethod, params common.RequestParams, timeout int) common.RequestInfo {
	normalizedPath := strings.TrimRight(path, "/")
	if normalizedPath == "" {
		normalizedPath = "/"
	}

	request := common.RequestInfo{
		BaseUrl:   baseURL,
		Path:      normalizedPath,
		Method:    method,
		Timestamp: time.Now(),
	}

	// Construct the URL
	fullURL, err := constructURL(baseURL, normalizedPath, params.PathParams, params.QueryParams)
	if err != nil {
		request.Errors = append(request.Errors, err.Error())
		return request
	}

	// Prepare request body and content type
	reqBody, contentType, err := prepareRequestBody(params)
	if err != nil {
		request.Errors = append(request.Errors, err.Error())
		return request
	}

	// Check for escape characters in headers
	hasEscapeChars := false
	for key, value := range params.HeaderParams {
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
	// Create and send the request based on the presence of escape characters
	if !hasEscapeChars {
		resp, err := sendRequest(method, fullURL.String(), reqBody, contentType, params.HeaderParams, timeout)
		if err != nil {
			request.Errors = append(request.Errors, err.Error())
			return request
		}
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
		resp, err := sendFastHTTPRequest(string(method), fullURL.String(), responseBody, contentType, params.HeaderParams)
		if err != nil {
			request.Errors = append(request.Errors, err.Error())
			return request
		}
		statusCode = resp.StatusCode()
		responseBody = string(resp.Body())
		resp.Header.VisitAll(func(key, value []byte) {
			responseHeader[string(key)] = string(value)
		})
		fasthttp.ReleaseResponse(resp)
	}

	// Populate report
	populateReport(&request, statusCode, responseHeader, responseBody, params)

	return request
}

func constructURL(baseURL, path string, pathParams, queryParams map[string]string) (*url.URL, error) {
	fullURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	endpoint := path
	for key, value := range pathParams {
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

func prepareRequestBody(params common.RequestParams) (io.Reader, string, error) {
	if params.BodyParams != "" {
		if json.Valid([]byte(params.BodyParams)) {
			return strings.NewReader(params.BodyParams), "application/json", nil
		}
		return bytes.NewReader([]byte(params.BodyParams)), "text/plain", nil
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

func sendRequest(method common.HttpMethod, url string, body io.Reader, contentType string, headers map[string]string, timeout int) (*http.Response, error) {
	req, err := http.NewRequest(string(method), url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, nil
}

func sendFastHTTPRequest(method, url string, body string, contentType string, headers map[string]string) (*fasthttp.Response, error) {
	// Prepare the fasthttp request and response objects
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(url)
	req.Header.SetMethod(method)
	req.SetBodyString(body)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	err := fasthttp.Do(req, resp)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, nil
}

func populateReport(report *common.RequestInfo, statusCode int, headers map[string]string, body string, params common.RequestParams) {
	if headers != nil {
		report.ResponseHeaders = make(map[string]string)
		for key, values := range headers {
			report.ResponseHeaders[key] = values
		}
	}

	report.ResponseBody = &body
	report.StatusCode = &statusCode

	if len(params.PathParams) > 0 {
		report.PathParams = params.PathParams
	}
	if len(params.QueryParams) > 0 {
		report.QueryParams = params.QueryParams
	}
	if len(params.HeaderParams) > 0 {
		report.HeaderParams = params.HeaderParams
	}
	if params.BodyParams != "" {
		report.BodyParams = &params.BodyParams
	}
	if len(params.FormParams) > 0 {
		report.FormParams = params.FormParams
	}
	if len(params.MultipartParams) > 0 {
		report.MultipartParams = params.MultipartParams
	}
}
