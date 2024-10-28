package webserver

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type BufferOverflowContentHeaderLibrary struct{}

func (BufferOverflowContentHeaderLib *BufferOverflowContentHeaderLibrary) ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	// Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNameBufferOverflowContentHeader, Timestamp: time.Now()}
	errors := []string{}
	finding := false

	// Deploy payload
	payload := bytes.Repeat([]byte("A"), 5000)
	headers := map[string]string{
		"Host":           target,
		"Content-Length": "4294967295",
		"Connection":     "close",
	}

	request := webscan.GeneralRequestInfo{Method: webscan.HttpMethodPost, Url: target, Headers: headers}

	req, err := http.NewRequest("POST", target, bytes.NewBuffer(payload))
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		errorMessage := err.Error()
		errors = append(errors, errorMessage)
		response := webscan.GeneralResponseInfo{Error: &errorMessage}
		GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &request, Response: &response}
		attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
		return &attempt, errors
	}
	response := webscan.GeneralResponseInfo{
		StatusCode: &resp.StatusCode,
	}
	err = resp.Body.Close()
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	// Marshal structs
	GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &webscan.GeneralRequestInfo{Method: webscan.HttpMethodPost, Url: target, Headers: headers}, Response: &response}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
	finding = BufferOverflowContentHeaderLib.AnalyzeResponse(webscan.NewResponseUnionFromGeneralResponse(&response))
	attempt.Finding = finding
	return &attempt, errors
}

func (BufferOverflowContentHeaderLib *BufferOverflowContentHeaderLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	if response.GeneralResponse.StatusCode == nil {
		return false
	}
	return *response.GeneralResponse.StatusCode >= 500
}
