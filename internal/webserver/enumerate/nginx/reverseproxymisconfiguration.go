package webserver

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type ReverseProxyCheckLibrary struct{}

func (ReverseProxyCheckLib *ReverseProxyCheckLibrary) ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	//Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNameReverseProxyMisconfiguration, Timestamp: time.Now()}
	errors := []string{}

	// Enumerate target
	params := map[string]string{
		"url": url.QueryEscape("http://127.0.0.1:80"),
	}
	attackURL := target + "/?url=" + params["url"]
	request := webscan.GeneralRequestInfo{
		Method: webscan.HttpMethodGet,
		Url:    attackURL,
		Params: params,
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
		errors = append(errors, err.Error())
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
	response := webscan.GeneralResponseInfo{
		StatusCode: &resp.StatusCode,
		Body:       &bodyStr,
	}
	err = resp.Body.Close()
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	// Marshal structs
	GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &request, Response: &response}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
	finding := ReverseProxyCheckLib.AnalyzeResponse(webscan.NewResponseUnionFromGeneralResponse(&response))
	attempt.Finding = finding
	return &attempt, errors
}

func (ReverseProxyCheckLib *ReverseProxyCheckLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	if response.GeneralResponse.StatusCode == nil {
		return false
	}

	if *response.GeneralResponse.StatusCode != http.StatusOK {
		return false
	}
	internalIndicators := []string{
		"nginx",
		"localhost",
	}
	for _, indicator := range internalIndicators {
		if response.GeneralResponse.Body != nil && strings.Contains(*response.GeneralResponse.Body, indicator) {
			finding := true
			return finding
		}
	}
	return false
}
