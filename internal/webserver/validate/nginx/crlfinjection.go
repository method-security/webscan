package webserver

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type CRLFInjectionLibrary struct{}

func (CRLFInjectionLib *CRLFInjectionLibrary) ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	// Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNameCrlfInjection, Timestamp: time.Now()}
	errors := []string{}

	// Enumerate target
	crlfPayload := "/%0d%0aSet-Cookie:%20crlfInjected=1"
	attackURL := target + crlfPayload
	request := webscan.GeneralRequestInfo{
		Method: webscan.HttpMethodGet,
		Url:    attackURL,
	}
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(attackURL)
	if err != nil {
		errorMessage := err.Error()
		errors = append(errors, errorMessage)
		response := webscan.GeneralResponseInfo{Error: &errorMessage}
		GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &request, Response: &response}
		attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
		return &attempt, errors
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}
	bodyStr := string(body)
	headerMap := make(map[string]string)
	for key, values := range resp.Header {
		headerMap[key] = strings.Join(values, ", ")
	}

	response := webscan.GeneralResponseInfo{
		StatusCode: &resp.StatusCode,
		Body:       &bodyStr,
		Headers:    headerMap,
	}

	// Close the response body
	err = resp.Body.Close()
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	// Marshal structs
	GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &request, Response: &response}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
	finding := CRLFInjectionLib.AnalyzeResponse(webscan.NewResponseUnionFromGeneralResponse(&response))
	attempt.Finding = finding
	return &attempt, errors
}

func (CRLFInjectionLib *CRLFInjectionLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	if response.GeneralResponse.StatusCode == nil {
		return false
	}
	if *response.GeneralResponse.StatusCode == http.StatusOK {
		if setCookieHeader, ok := response.GeneralResponse.Headers["Set-Cookie"]; ok {
			if strings.Contains(setCookieHeader, "crlfInjected=1") {
				return true
			}
		}
	}
	return false
}
