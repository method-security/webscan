package webapplication

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type NginxLibrary struct{}

var nginxPaths = []string{
	"", // Root
	"/nginx_status",
	"/status",
	"/.nginx-debian.html",
	"/50x.html",
	"/404.html",
}

func (ngLib *NginxLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromWebApplicationModule(webscan.WebApplicationModuleNginx),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}

	for _, path := range nginxPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if ngLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (ngLib *NginxLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseHeaders == nil {
		return false
	}

	// Check for "Server" or "server" headers
	for _, headerKey := range []string{"Server", "server", "X-Powered-By", "x-powered-by"} {
		if serverHeader, ok := response.ResponseHeaders[headerKey]; ok {
			if strings.Contains(strings.ToLower(serverHeader), "nginx") {
				return true
			}
		}
	}

	// If no body is present, we already checked headers
	if response.ResponseBody == nil {
		return false
	}

	// Check body for Nginx indicators
	nginxBodyIndicators := []string{
		"<title>welcome to nginx</title>",
		"<title>nginx error</title>",
		"<title>test page for nginx</title>",
		"<h1>welcome to nginx!</h1>",
		"<center>nginx</center>",
		"<hr><center>nginx/",
		"powered by nginx",
	}

	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range nginxBodyIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}
