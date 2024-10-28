package webserver

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PathTraversal(target string, timeout int, commonExposedPaths []string) ([]*webscan.PathInfo, []string) {
	//Initialize structs
	var paths []*webscan.PathInfo
	errors := []string{}

	// Enumerate paths
	for _, filepath := range commonExposedPaths {
		fullURL := target + filepath
		request := webscan.GeneralRequestInfo{
			Method: webscan.HttpMethodGet,
			Url:    fullURL,
		}
		path := webscan.PathInfo{Path: filepath, Request: &request}

		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Millisecond,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get(fullURL)
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
		paths = append(paths, &path)
	}
	return paths, errors
}
