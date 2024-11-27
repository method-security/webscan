package cloudbucket

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type AzureBlobLibrary struct{}

func (azureLib *AzureBlobLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttempt, []string) {
	attempt := webscan.AppFingerprintAttempt{
		Name:      webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob),
		Timestamp: time.Now(),
	}
	errors := []string{}

	// Parse target URL to separate base URL and path
	parsedURL, err := url.Parse(target)
	baseURL := target
	targetpath := "/"
	if err == nil && parsedURL.Path != "" {
		baseURL = parsedURL.Scheme + "://" + parsedURL.Host
		targetpath = parsedURL.Path
	}

	request := webscan.AppFingerprintRequestInfo{
		BaseUrl: baseURL,
		Path:    targetpath,
		Method:  webscan.HttpMethodGet,
	}
	attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.AppFingerprintAttemptInfo{Request: &request})

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	fullURL := baseURL + targetpath
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		errors = append(errors, err.Error())
		attempt.AttemptInfo[0].Errors = errors
		attempt.Finding = false
		return &attempt, errors
	}

	resp, err := client.Do(req)
	if err != nil {
		errors = append(errors, err.Error())
		attempt.AttemptInfo[0].Errors = errors
		attempt.Finding = false
		return &attempt, errors
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
		attempt.AttemptInfo[0].Errors = errors
		attempt.Finding = false
		return &attempt, errors
	}

	bodyStr := string(body)
	err = resp.Body.Close()
	if err != nil {
		errors = append(errors, err.Error())
		attempt.AttemptInfo[0].Errors = errors
		attempt.Finding = false
		return &attempt, errors
	}

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0]
	}

	statusCode := resp.StatusCode
	responseInfo := &webscan.AppFingerprintResponseInfo{
		StatusCode:      &statusCode,
		ResponseHeaders: headers,
		ResponseBody:    &bodyStr,
	}

	attempt.AttemptInfo[0].Response = responseInfo
	attempt.Finding = azureLib.AnalyzeResponse(responseInfo)

	return &attempt, errors
}

func (azureLib *AzureBlobLibrary) AnalyzeResponse(response *webscan.AppFingerprintResponseInfo) bool {
	if response == nil {
		return false
	}

	// Check for Azure Blob specific headers and server
	if response.ResponseHeaders != nil {
		// Check for Microsoft Azure Storage server header
		server, exists := response.ResponseHeaders["Server"]
		if exists && strings.Contains(strings.ToLower(server), "microsoft") &&
			strings.Contains(strings.ToLower(server), "blob") {
			return true
		}

		// Check for x-ms-blob-type header
		if _, exists := response.ResponseHeaders["X-Ms-Blob-Type"]; exists {
			return true
		}
	}

	return false
}
