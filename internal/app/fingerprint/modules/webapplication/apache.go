package webapplication

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type ApacheLibrary struct{}

var apachePaths = []string{
	"", // Root
	"/server-status",
	"/icons/",
	"/manual/",
	"/cgi-bin/",
	"/.htaccess",
}

func (apLib *ApacheLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromWebApplicationModule(webscan.WebApplicationModuleApache),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}

	for _, path := range apachePaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if apLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (apLib *ApacheLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseBody == nil || response.ResponseHeaders == nil {
		return false
	}

	// We're interested in responses even if they're not 200 OK
	// Apache often reveals itself in error pages too

	// Check headers for Apache indicators
	for _, headerKey := range []string{"Server", "server", "X-Powered-By", "x-powered-by"} {
		if serverHeader, ok := response.ResponseHeaders[headerKey]; ok {
			if strings.Contains(strings.ToLower(serverHeader), "apache") {
				return true
			}
		}
	}

	// Check body for Apache indicators
	apacheBodyIndicators := []string{
		"<address>apache",
		"apache server at",
		"powered by apache",
		"apache/",
		"<title>apache http server",
		"<title>apache status</title>",
		"apache tomcat",
	}

	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range apacheBodyIndicators {
		if strings.Contains(body, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}
