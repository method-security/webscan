package cloudbucket

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type AzureBlobLibrary struct{}

func (azureLib *AzureBlobLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	request := utils.PerformRequestScan(baseURL, parsedTargetPath, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
	errors = append(errors, request.Errors...)

	attempt.Finding = azureLib.AnalyzeResponse(&request)

	attempt.Requests = []*common.RequestInfo{&request}
	return &attempt, errors
}

func (azureLib *AzureBlobLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil {
		return false
	}

	// Check for Azure Blob specific headers and server
	if response.ResponseHeaders != nil {
		// Check for Microsoft Azure Storage server header
		server, exists := response.ResponseHeaders["Server"]
		if exists && strings.Contains(strings.ToLower(server), "microsoft") &&
			strings.Contains(strings.ToLower(server), "blob") {
			return true
		}

		// Check for x-ms-blob-type header
		if _, exists := response.ResponseHeaders["X-Ms-Blob-Type"]; exists {
			return true
		}
	}

	return false
}
