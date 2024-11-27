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

// extractContainerPath extracts the container path from the URL
// Example: https://account.blob.core.windows.net/container/path -> https://account.blob.core.windows.net/container
func extractContainerPath(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Split path by '/' and take first two parts (empty and container name)
	pathParts := strings.Split(parsedURL.Path, "/")
	if len(pathParts) < 2 {
		return urlStr
	}

	containerPath := pathParts[1]
	parsedURL.Path = "/" + containerPath
	return parsedURL.String()
}

func (azureLib *AzureBlobLibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	// Initialize structs
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob),
		Timestamp: time.Now(),
	}
	errors := []string{}

	// Extract container path and add metadata query parameters
	containerPath := extractContainerPath(target)
	metadataURL := containerPath + "?restype=container&comp=metadata"

	request := webscan.DetectRequestInfo{
		BaseUrl: containerPath,
		Path:    "?restype=container&comp=metadata",
		Method:  webscan.HttpMethodGet,
	}
	attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request})

	// Create HTTP client with TLS skip verify
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make request to target
	req, err := http.NewRequest("GET", metadataURL, nil)
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

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
		attempt.AttemptInfo[0].Errors = errors
		attempt.Finding = false
		return &attempt, errors
	}

	// Convert body to string
	bodyStr := string(body)
	err = resp.Body.Close()
	if err != nil {
		errors = append(errors, err.Error())
		attempt.AttemptInfo[0].Errors = errors
		attempt.Finding = false
		return &attempt, errors
	}

	// Create response info
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = values[0]
	}

	statusCode := resp.StatusCode
	responseInfo := &webscan.DetectResponseInfo{
		StatusCode:      &statusCode,
		ResponseHeaders: headers,
		ResponseBody:    &bodyStr,
	}

	attempt.AttemptInfo[0].Response = responseInfo
	attempt.Finding = azureLib.AnalyzeResponse(responseInfo)

	return &attempt, errors
}

func (azureLib *AzureBlobLibrary) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	if response == nil {
		return false
	}

	if response.StatusCode != nil {
		if *response.StatusCode != 200 && *response.StatusCode != 403 {
			return false
		}
	}

	// Check for Azure Blob specific headers and server
	if response.ResponseHeaders != nil {
		// Check for Microsoft Azure Storage server header
		server, exists := response.ResponseHeaders["Server"]
		if !exists || !strings.Contains(strings.ToLower(server), "windows-azure-blob") {
			return false
		}

		// Check for required Azure Blob Storage headers
		requiredHeaders := []string{
			"x-ms-version",          // Azure Storage service version
			"x-ms-request-id",       // Request ID for troubleshooting
			"x-ms-blob-type",        // Type of blob (BlockBlob, PageBlob, etc)
			"x-ms-server-encrypted", // Indicates if content is encrypted
		}

		headerCount := 0
		for _, required := range requiredHeaders {
			if _, exists := response.ResponseHeaders[required]; exists {
				headerCount++
			}
		}

		// Require at least 2 Azure Blob specific headers to confirm
		return headerCount >= 2
	}

	return false
}
