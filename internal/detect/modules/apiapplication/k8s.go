package apiapplication

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type K8sLibrary struct{}

func (k8sLib *K8sLibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleK8S),
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
	fmt.Println(fullURL)

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
	attempt.Finding = k8sLib.AnalyzeResponse(responseInfo)

	return &attempt, errors
}

func (k8sLib *K8sLibrary) AnalyzeResponse(response *webscan.DetectResponseInfo) bool {
	if response == nil || response.ResponseHeaders == nil {
		return false
	}

	k8sHeaders := []string{"X-Kubernetes-Pf-Flowschema-Uid", "X-Kubernetes-Pf-Prioritylevel-Uid"}

	// Check for presence of any K8s specific headers
	for _, header := range k8sHeaders {
		if _, exists := response.ResponseHeaders[header]; exists {
			return true
		}
	}

	return false
}
