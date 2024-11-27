package apiapplication

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"time"

	helper "github.com/Method-Security/webscan/configs"
	webscan "github.com/Method-Security/webscan/generated/go"
)

type K8sLibrary struct{}

func (k8sLib *K8sLibrary) ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string) {
	// Initialize structs
	attempt := webscan.DetectAttempt{
		Name:      webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleK8S),
		Timestamp: time.Now(),
	}
	request := webscan.DetectRequestInfo{
		BaseUrl: target,
		Path:    helper.ExtractURLPath(target),
		Method:  webscan.HttpMethodGet,
	}
	attempt.AttemptInfo = append(attempt.AttemptInfo, &webscan.DetectAttemptInfo{Request: &request})
	errors := []string{}

	// Create HTTP client with TLS skip verify
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make request to target
	req, err := http.NewRequest("GET", target, nil)
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

	// Analyze response for K8s headers
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
