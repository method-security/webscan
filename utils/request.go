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

type RequestOptions struct {
	BaseURL         string
	Path            string
	Method          common.HttpMethod
	BaseHeaders     map[string][]string
	Params          common.RequestParams
	FollowRedirects bool
	Insecure        bool
	Timeout         int
}

func PerformRequestScan(options RequestOptions) common.RequestInfo {
	request := common.RequestInfo{
		BaseUrl:     options.BaseURL,
		Path:        options.Path,
		Method:      options.Method,
		BaseHeaders: options.BaseHeaders,
	}

	// Construct the URL
	fullURL, err := constructURL(options.BaseURL, options.Path, options.Params.PathParams, options.Params.QueryParams)
	if err != nil {
		request.Errors = append(request.Errors, err.Error())
		return request
	}

	// Prepare request body and content type
	reqBody, contentType, err := prepareRequestBody(options.Params.Body)
	if err != nil {
		request.Errors = append(request.Errors, err.Error())
		return request
	}

	// Check for escape characters in headers
	hasEscapeChars := false
	for key, values := range options.Params.HeaderParams {
		if strings.Contains(key, "\r") || strings.Contains(key, "\n") || strings.Contains(key, "\\") || strings.Contains(key, "\u0000") {
			hasEscapeChars = true
			break
		}
		for _, value := range values {
			if strings.Contains(value, "\r") || strings.Contains(value, "\n") || strings.Contains(value, "\\") || strings.Contains(value, "\u0000") {
				hasEscapeChars = true
				break
			}
		}
		if hasEscapeChars {
			break
		}
	}

	var statusCode int
	var responseBody string
	var timestamp = time.Now()
	var receivedAt time.Time
	var sizeBytes int
	responseHeaders := make(map[string][]string)
	// Create and send the request based on the presence of escape characters
	if !hasEscapeChars {
		resp, redirectChain, err := sendRequest(options.Method, fullURL.String(), reqBody, contentType, options.Params.HeaderParams, options.Timeout, options.FollowRedirects, options.Insecure)
		receivedAt = time.Now()
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
		sizeBytes = int(len(body))
		responseHeaders = resp.Header

		// Populate report
		populateReport(&request, statusCode, responseHeaders, responseBody, options.Params, redirectChain, timestamp, receivedAt, &sizeBytes)
	} else {
		// Use sendFastHTTPRequest if escape characters are present
		resp, redirectChain, err := sendFastHTTPRequest(string(options.Method), fullURL.String(), responseBody, contentType, options.Params.HeaderParams, options.FollowRedirects)
		receivedAt = time.Now()
		if err != nil {
			request.Errors = append(request.Errors, err.Error())
			return request
		}
		statusCode = resp.StatusCode()
		responseBody = string(resp.Body())
		sizeBytes = int(len(resp.Body()))
		resp.Header.VisitAll(func(key, value []byte) {
			responseHeaders[string(key)] = append(responseHeaders[string(key)], string(value))
		})
		fasthttp.ReleaseResponse(resp)
		// Populate report
		populateReport(&request, statusCode, responseHeaders, responseBody, options.Params, redirectChain, timestamp, receivedAt, &sizeBytes)
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

func prepareRequestBody(body *common.Body) (io.Reader, string, error) {
	if body == nil {
		return nil, "", nil
	}

	switch body.GetKind() {
	case "text":
		if body.GetText() != nil {
			return strings.NewReader(body.GetText().GetValue()), "text/plain", nil
		}
	case "json":
		if body.GetJson() != nil {
			jsonBytes, err := json.Marshal(body.GetJson().GetData())
			if err != nil {
				return nil, "", err
			}
			return bytes.NewReader(jsonBytes), "application/json", nil
		}
	case "form":
		if body.GetForm() != nil {
			formValues := url.Values{}
			for key, value := range body.GetForm().GetFields() {
				formValues.Set(key, value)
			}
			encodedForm := formValues.Encode()
			return strings.NewReader(encodedForm), "application/x-www-form-urlencoded", nil
		}
	case "multipart":
		if body.GetMultipart() != nil {
			buf := &bytes.Buffer{}
			writer := multipart.NewWriter(buf)
			for _, part := range body.GetMultipart().GetParts() {
				if part.GetContent() != nil {
					// Assume each part is a file for simplicity
					formFile, err := writer.CreateFormFile("file", "file.bin")
					if err != nil {
						return nil, "", err
					}
					_, err = formFile.Write(part.GetContent().GetBase64())
					if err != nil {
						return nil, "", err
					}
				}
				for key, value := range part.GetHeaders() {
					writer.WriteField(key, value)
				}
			}
			if err := writer.Close(); err != nil {
				return nil, "", err
			}
			return buf, writer.FormDataContentType(), nil
		}
	case "binary":
		if body.GetBinary() != nil {
			return bytes.NewReader(body.GetBinary().GetBase64()), "application/octet-stream", nil
		}
	}
	return nil, "", nil
}

func sendRequest(method common.HttpMethod, url string, body io.Reader, contentType string, headers map[string][]string, timeout int, followRedirects bool, insecure bool) (*http.Response, []string, error) {
	req, err := http.NewRequest(string(method), url, body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header = headers

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	redirectChain := []string{url}
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}
			redirectChain = append(redirectChain, req.URL.String())
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, redirectChain, nil
}

func sendFastHTTPRequest(method, url string, body string, contentType string, headers map[string][]string, followRedirects bool) (*fasthttp.Response, []string, error) {
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

	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	redirectChain := []string{url}
	var err error
	if followRedirects {
		err = fasthttp.DoRedirects(req, resp, 10) // Follow up to 10 redirects
		// For FastHTTP, we need to manually track redirects
		if err == nil {
			location := resp.Header.Peek("Location")
			if len(location) > 0 {
				redirectChain = append(redirectChain, string(location))
			}
		}
	} else {
		err = fasthttp.Do(req, resp)
	}
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, nil, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, redirectChain, nil
}

// parseResponseBody parses the response body based on the Content-Type header and returns a *common.Body
func parseResponseBody(body string, contentType string) *common.Body {
	switch {
	case strings.Contains(contentType, "application/json"):
		var jsonData interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			return common.NewBodyFromJson(&common.JsonBody{Data: jsonData})
		}
		return common.NewBodyFromText(&common.TextBody{Value: body})
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		formVals, err := url.ParseQuery(body)
		if err == nil {
			fields := make(map[string]string)
			for k, v := range formVals {
				if len(v) > 0 {
					fields[k] = v[0]
				}
			}
			return common.NewBodyFromForm(&common.FormBody{Fields: fields})
		}
		return common.NewBodyFromText(&common.TextBody{Value: body})
	case strings.Contains(contentType, "text/"):
		return common.NewBodyFromText(&common.TextBody{Value: body})
	case strings.Contains(contentType, "multipart/"):
		// For now, just store as text. Parsing multipart is complex and not always needed.
		return common.NewBodyFromText(&common.TextBody{Value: body})
	case strings.Contains(contentType, "application/octet-stream"):
		// Could handle binary, but for now, just store as text
		return common.NewBodyFromText(&common.TextBody{Value: body})
	default:
		return common.NewBodyFromText(&common.TextBody{Value: body})
	}
}

func populateReport(report *common.RequestInfo, statusCode int, headers map[string][]string, body string, params common.RequestParams, redirectChain []string, timestamp time.Time, receivedAt time.Time, sizeBytes *int) {
	if headers != nil {
		report.ResponseHeaders = make(map[string][]string)
		for key, values := range headers {
			report.ResponseHeaders[key] = values
		}
	}

	// Determine Content-Type
	contentType := ""
	if headers != nil {
		if ctVals, ok := headers["Content-Type"]; ok && len(ctVals) > 0 {
			contentType = ctVals[0]
		}
	}

	report.ResponseBody = parseResponseBody(body, contentType)
	report.StatusCode = &statusCode
	report.RedirectChain = redirectChain
	report.Timestamp = timestamp
	report.ReceivedAt = &receivedAt
	report.SizeBytes = sizeBytes

	if len(params.PathParams) > 0 {
		report.Parameters.PathParams = params.PathParams
	}
	if len(params.QueryParams) > 0 {
		report.Parameters.QueryParams = params.QueryParams
	}
}

// GetHeader is a generic header helper (case‑insensitive)
func GetHeader(r *common.RequestInfo, name string) string {
	if r.ResponseHeaders == nil {
		return ""
	}
	if v, ok := r.ResponseHeaders[name]; ok && len(v) > 0 {
		return v[0]
	}
	for hn, hv := range r.ResponseHeaders {
		if strings.EqualFold(hn, name) && len(hv) > 0 {
			return hv[0]
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
