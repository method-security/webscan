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

type AwsS3Library struct{}

func (awsLib *AwsS3Library) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAwss3),
		Timestamp: time.Now(),
	}

	// Parse target URL to separate base URL and path
	parsedURL, err := url.Parse(target)
	baseURL := target
	targetpath := "/"
	if err == nil && parsedURL.Path != "" {
		baseURL = parsedURL.Scheme + "://" + parsedURL.Host
		targetpath = parsedURL.Path
	}

	request := webscan.DetectRequestInfo{
		BaseUrl: baseURL,
		Path:    targetpath,
		Method:  webscan.HttpMethodGet,
	}
	attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request})
	errors := []string{}

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
	responseInfo := &webscan.DetectResponseInfo{
		StatusCode:      &statusCode,
		ResponseHeaders: headers,
		ResponseBody:    &bodyStr,
	}

	attempt.AttemptInfo[0].Response = responseInfo
	attempt.Finding = awsLib.AnalyzeResponse(responseInfo)

	return &attempt, errors
}

func (awsLib *AwsS3Library) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	if response == nil {
		return false
	}

	// Check status code (200 or 403 as per yaml template)
	if response.StatusCode != nil {
		if *response.StatusCode != 200 && *response.StatusCode != 403 {
			return false
		}
	}

	// Check for AWS S3 specific headers and server
	if response.ResponseHeaders != nil {
		// Check for Amazon S3 server header
		server, exists := response.ResponseHeaders["Server"]
		if !exists || !strings.Contains(strings.ToLower(server), "amazons3") {
			return false
		}

		// Check for required AWS headers
		requiredHeaders := []string{
			"x-amz-bucket-region",
		}

		for _, header := range requiredHeaders {
			found := false
			for key := range response.ResponseHeaders {
				if strings.EqualFold(key, header) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		return true
	}

	return false
}
