package apiapplication

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type FastAPILibrary struct{}

var fastapiPaths = []string{
	"/docs",
	"/redoc",
	"/openapi.json",
}

func (fastapiLib *FastAPILibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleFastapi),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}
	for _, path := range fastapiPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if fastapiLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (fastapiLib *FastAPILibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	// Ensure the response and its body are valid
	if response == nil || response.ResponseBody == nil || response.ResponseHeaders == nil {
		return false
	}

	// Indicators to identify FastAPI responses in the body
	bodyIndicators := []string{
		"FastAPI - Swagger UI",
		"FastAPI - ReDoc",
		"fastapi.tiangolo.com",
	}

	// Headers that may indicate a FastAPI response
	headerIndicators := map[string]string{
		"x-process-time": "", // FastAPI default header
	}

	// Check body for FastAPI-specific indicators
	body := *response.ResponseBody
	for _, indicator := range bodyIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	// Check headers for FastAPI-specific indicators
	for key, expectedValue := range headerIndicators {
		if value, exists := response.ResponseHeaders[key]; exists {
			if expectedValue == "" || strings.Contains(value, expectedValue) {
				return true
			}
		}
	}

	return false
}
