package cloudbucket

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type AwsS3Library struct{}

func (awsLib *AwsS3Library) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAwss3),
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

	attempt.Finding = awsLib.AnalyzeResponse(&request)

	attempt.Requests = []*common.RequestInfo{&request}
	return &attempt, errors
}

func (awsLib *AwsS3Library) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseHeaders == nil {
		return false
	}

	if *response.StatusCode != 200 && *response.StatusCode != 403 {
		return false
	}

	// Check for Amazon S3 server header
	for key, headerValue := range response.ResponseHeaders {
		if strings.EqualFold(key, "Server") {
			if strings.Contains(strings.ToLower(strings.TrimSpace(headerValue)), "amazons3") {
				return true
			}
		}
	}

	// Check for AWS bucket region header
	_, hasRegionHeader := response.ResponseHeaders["x-amz-bucket-region"]

	return hasRegionHeader
}
