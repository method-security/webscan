package apiapplication

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type WordPressLibrary struct{}

var wordpressPaths = []string{
	"", // Root
	"/wp-login.php",
	"/wp-admin/",
	"/xmlrpc.php",
	"/wp-content/",
	"/wp-includes/",
}

func (wpLib *WordPressLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleWordpress),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}

	for _, path := range wordpressPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if wpLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (wpLib *WordPressLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseBody == nil || response.ResponseHeaders == nil {
		return false
	}

	if *response.StatusCode != 200 && *response.StatusCode != 403 {
		return false
	}

	// Check body for indicators
	wordpressBodyIndicators := []string{
		"wp-content/", "wp-includes/", "<meta name=\"generator\" content=\"WordPress", "/wp-json", "/wp-admin/admin-ajax.php",
	}
	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range wordpressBodyIndicators {
		if strings.Contains(body, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check headers for indicators
	wordpressHeadersIndicators := []string{"x-pingback", "link", "x-powered-by"}
	for header, values := range response.ResponseHeaders {
		headerLower := strings.ToLower(header)
		for _, wpHeader := range wordpressHeadersIndicators {
			if headerLower == strings.ToLower(wpHeader) {
				for _, value := range values {
					if strings.Contains(strings.ToLower(string(value)), "wp-json") || strings.Contains(strings.ToLower(string(value)), "wp engine") || strings.Contains(strings.ToLower(string(value)), "wordpress") {
						return true
					}
				}
			}
		}
	}

	return false
}
