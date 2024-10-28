package webserver

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type XPoweredByHeaderGrabLibrary struct{}

func (XPoweredByHeaderGrabLib *XPoweredByHeaderGrabLibrary) ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	//Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNameXPoweredByHeaderGrab, Timestamp: time.Now()}
	errors := []string{}
	request := webscan.GeneralRequestInfo{
		Method: webscan.HttpMethodGet,
		Url:    target,
	}
	response := webscan.VersionEnumerateResponseInfo{}

	// Enumerate target
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(target)
	if err != nil {
		errorMessage := err.Error()
		errors = append(errors, errorMessage)
		response.Error = &errorMessage
		VersionEnumerateAttemptInfo := webscan.VersionEnumerateAttemptInfo{Request: &request, Response: &response}
		attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromVersionAttempt(&VersionEnumerateAttemptInfo)
		return &attempt, errors
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")

	if xPoweredBy != "" {
		typeVersion := parseXPoweredByHeader(xPoweredBy)
		response = webscan.VersionEnumerateResponseInfo{
			StatusCode:    &resp.StatusCode,
			VersionType:   &typeVersion[0],
			VersionNumber: &typeVersion[1],
		}
	} else {
		response = webscan.VersionEnumerateResponseInfo{
			StatusCode: &resp.StatusCode,
		}
	}
	err = resp.Body.Close()
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	// Marshal structs
	VersionEnumerateAttemptInfo := webscan.VersionEnumerateAttemptInfo{Request: &request, Response: &response}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromVersionAttempt(&VersionEnumerateAttemptInfo)
	finding := XPoweredByHeaderGrabLib.AnalyzeResponse(webscan.NewResponseUnionFromVersionEnumerateResponse(&response))
	attempt.Finding = finding
	return &attempt, errors
}

func (XPoweredByHeaderGrabLib *XPoweredByHeaderGrabLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	return response.VersionEnumerateResponse.VersionType != nil
}

func parseXPoweredByHeader(headerValue string) [2]string {
	var typeVersion [2]string
	typeVersion[0] = headerValue
	typeVersion[1] = ""
	parts := strings.Split(headerValue, "/")
	if len(parts) == 2 {
		typeVersion[0] = parts[0]
		typeVersion[1] = parts[1]
	}
	return typeVersion
}
