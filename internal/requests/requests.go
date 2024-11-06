package requests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformRequestScan(baseURL, path, method string, params webscan.RequestParams, vulnTypes []string) webscan.RequestReport {
	report := webscan.RequestReport{
		BaseUrl: baseURL,
		Path:    path,
	}

	// Validate and set HTTP method
	httpMethod := strings.ToUpper(method)
	if !isValidHTTPMethod(httpMethod) {
		report.Errors = append(report.Errors, fmt.Sprintf("Invalid HTTP method: %s", method))
		return report
	}
	report.Method = webscan.HttpMethod(httpMethod)

	// Parse parameters
	parsedParams, err := parseAllParams(params)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Add parsed parameters to Report
	report.PathParams = parsedParams.PathParams
	report.QueryParams = parsedParams.QueryParams
	report.HeaderParams = parsedParams.HeaderParams
	report.BodyParams = &parsedParams.BodyParams
	report.FormParams = parsedParams.FormParams
	report.MultipartParams = parsedParams.MultipartParams

	// Construct the URL
	fullURL, err := constructURL(baseURL, path, parsedParams.PathParams, parsedParams.QueryParams)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Prepare request body and content type
	reqBody, contentType, err := prepareRequestBody(parsedParams)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Check for escape characters in headers
	hasEscapeChars := false
	for _, value := range parsedParams.HeaderParams {
		if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
			hasEscapeChars = true
			break
		}
	}

	var statusCode int
	var responseBody string
	var responseHeader map[string]string
	responseHeader = make(map[string]string)
	var resp *http.Response

	// Create and send the request based on the presence of escape characters
	if !hasEscapeChars {
		resp, err = sendRequest(httpMethod, fullURL.String(), reqBody, contentType, parsedParams.HeaderParams)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Error closing response body: %v", err))
			}
		}()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to read response body: %v", err))
			return report
		}
		statusCode = resp.StatusCode
		responseBody = string(body)
		for key, values := range resp.Header {
			if len(values) > 0 {
				responseHeader[key] = values[0]
			}
		}
	} else {
		// Use sendCurlRequest if escape characters are present
		statusCode, responseHeader, responseBody, err = sendCurlRequest(httpMethod, fullURL.String(), responseBody, contentType, parsedParams.HeaderParams)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
	}

	// Populate report
	populateReport(&report, statusCode, responseHeader, responseBody, parsedParams, vulnTypes)

	return report
}

func isValidHTTPMethod(method string) bool {
	validMethods := map[string]bool{
		string(webscan.HttpMethodGet):    true,
		string(webscan.HttpMethodPost):   true,
		string(webscan.HttpMethodPut):    true,
		string(webscan.HttpMethodDelete): true,
		string(webscan.HttpMethodPatch):  true,
	}
	return validMethods[method]
}

func parseJSONParams(jsonStr string) (map[string]string, error) {
	if jsonStr == "" {
		return nil, nil
	}

	var result map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	params := make(map[string]string)
	for key, value := range result {
		switch v := value.(type) {
		case string:
			params[key] = v
		default:
			stringValue, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal value for key %s: %v", key, err)
			}
			params[key] = string(stringValue)
		}
	}

	return params, nil
}

func parseAllParams(params webscan.RequestParams) (webscan.ParsedParams, error) {
	var parsed webscan.ParsedParams
	var err error

	parsed.PathParams, err = parseJSONParams(params.PathParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse path parameters: %v", err)
	}

	parsed.QueryParams, err = parseJSONParams(params.QueryParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse query parameters: %v", err)
	}

	parsed.HeaderParams, err = parseJSONParams(params.HeaderParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse header parameters: %v", err)
	}

	parsed.FormParams, err = parseJSONParams(params.FormParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse form parameters: %v", err)
	}

	parsed.MultipartParams, err = parseJSONParams(params.MultipartParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse multipart parameters: %v", err)
	}

	parsed.BodyParams = params.BodyParams

	return parsed, nil
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

func prepareRequestBody(params webscan.ParsedParams) (io.Reader, string, error) {
	if params.BodyParams != "" {
		if !json.Valid([]byte(params.BodyParams)) {
			return nil, "", fmt.Errorf("invalid JSON in body parameters")
		}
		return strings.NewReader(params.BodyParams), "application/json", nil
	}

	if len(params.FormParams) > 0 {
		formValues := url.Values{}
		for key, value := range params.FormParams {
			formValues.Add(key, value)
		}
		return strings.NewReader(formValues.Encode()), "application/x-www-form-urlencoded", nil
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

func sendRequest(method, url string, body io.Reader, contentType string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, nil
}

func sendCurlRequest(method, url string, body string, contentType string, headers map[string]string) (int, map[string]string, string, error) {
	cmdArgs := []string{"-i", "-X", method, url} // Add `-i` to include headers in the output

	for key, value := range headers {
		cmdArgs = append(cmdArgs, "-H", fmt.Sprintf("%s: %s", key, value))
	}

	if contentType != "" {
		cmdArgs = append(cmdArgs, "-H", fmt.Sprintf("Content-Type: %s", contentType))
	}

	if body != "" {
		cmdArgs = append(cmdArgs, "-d", body)
	}

	cmd := exec.Command("curl", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, nil, "", fmt.Errorf("failed to perform request: %v\nOutput: %s", err, string(output))
	}

	// Convert output to string and split headers and body
	outputStr := string(output)
	headerEnd := strings.Index(outputStr, "\r\n\r\n")
	if headerEnd == -1 {
		return 0, nil, "", fmt.Errorf("invalid response format: no headers found")
	}

	// Separate headers and body
	headerText := outputStr[:headerEnd]
	bodyText := outputStr[headerEnd+4:]

	// Extract the status code from the first line of headers
	headerLines := strings.Split(headerText, "\r\n")
	statusLine := headerLines[0]
	statusParts := strings.Split(statusLine, " ")
	if len(statusParts) < 2 {
		return 0, nil, "", fmt.Errorf("invalid status line: %s", statusLine)
	}
	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return 0, nil, "", fmt.Errorf("failed to parse status code: %v", err)
	}

	// Parse headers
	headersMap := make(map[string]string)
	for _, line := range headerLines[1:] {
		if strings.Contains(line, ": ") {
			parts := strings.SplitN(line, ": ", 2)
			headersMap[parts[0]] = parts[1]
		}
	}

	return statusCode, headersMap, bodyText, nil
}

func populateReport(report *webscan.RequestReport, statusCode int, headers map[string]string, body string, params webscan.ParsedParams, vulnTypes []string) {
	if headers != nil {
		report.ResponseHeaders = make(map[string]string)
		for key, values := range headers {
			report.ResponseHeaders[key] = values
		}
	}

	report.ResponseBody = body
	report.StatusCode = statusCode

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
	if len(vulnTypes) > 0 {
		report.VulnTypes = make([]webscan.VulnType, 0, len(vulnTypes))
		for _, vt := range vulnTypes {
			if vulnType, err := webscan.NewVulnTypeFromString(vt); err == nil {
				report.VulnTypes = append(report.VulnTypes, vulnType)
			} else {
				report.Errors = append(report.Errors, fmt.Sprintf("Invalid vulnerability type: %s", vt))
			}
		}
	}
}
