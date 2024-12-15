package apiapplication

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type SwaggerLibrary struct{}

var swaggerPaths = []string{
	"/swagger-ui-bundle.js",
	"/swagger-ui.html",
	"/swagger/index.html",
	"/swagger",
	"/api-docs",
	"/v2/api-docs",
	"/swagger/v1/swagger.json",
	"/api/swagger",
	"/swagger.json",
	"/swagger.yaml",
}

func (swaggerLib *SwaggerLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleSwagger),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}
	for _, path := range swaggerPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if swaggerLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (swaggerLib *SwaggerLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseBody == nil || response.ResponseHeaders == nil {
		return false
	}

	if *response.StatusCode != 200 {
		return false
	}

	swaggerIndicators := []string{
		"swagger:", "<div id=\"swagger-ui\">", "\"openapi\":",
		"\"paths\":", "\"components\":", "\"info\": {\"title\":",
		"Swagger UI", "loadSwaggerUI", "\"swagger\":",
	}
	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range swaggerIndicators {
		if strings.Contains(body, strings.ToLower(indicator)) {
			return true
		}
	}

	swaggerHeaders := []string{"x-swagger-router-basepath", "x-swagger-router-controller"}
	for header := range response.ResponseHeaders {
		headerLower := strings.ToLower(header)
		for _, swaggerHeader := range swaggerHeaders {
			if headerLower == strings.ToLower(swaggerHeader) {
				return true
			}
		}
	}

	return false
}
