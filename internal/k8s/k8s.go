package k8s

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformK8sScan(ctx context.Context, target string, timeout int) *webscan.K8SReport {
	resources := &webscan.K8SReport{Target: target}
	var errors []string

	paths := []string{"/api", "/livez", "/version"}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var K8sPaths []*webscan.K8SPathInfo
	for _, path := range paths {
		fullURL := fmt.Sprintf("%s%s", target, path)
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		err = resp.Body.Close()
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Check for Kubernetes headers
		headers := make(map[string]string)
		for key, values := range resp.Header {
			headers[key] = values[0]
		}

		// Marshal data
		bodyStr := string(body)
		statusCode := resp.StatusCode
		pathInfo := webscan.K8SPathInfo{
			Path:            path,
			Method:          webscan.HttpMethodGet,
			ResponseHeaders: headers,
			ResponseBody:    &bodyStr,
			ResponseStatus:  &statusCode,
			Timestamp:       time.Now(),
		}
		K8sPaths = append(K8sPaths, &pathInfo)
	}

	resources.K8SPaths = K8sPaths
	resources.Errors = errors
	return resources
}
