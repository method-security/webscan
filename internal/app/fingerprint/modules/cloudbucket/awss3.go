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
	if response == nil {
		return false
	}

	// Check status code (200 or 403 as per yaml template)
	if response.StatusCode != nil {
		if *response.StatusCode != 200 && *response.StatusCode != 403 {
			return false
		}
	}

	// Check for AWS S3 specific headers and server
	if response.ResponseHeaders != nil {
		// Check for Amazon S3 server header
		server, exists := response.ResponseHeaders["Server"]
		if !exists || !strings.Contains(strings.ToLower(server), "amazons3") {
			return false
		}

		// Check for required AWS headers
		requiredHeaders := []string{
			"x-amz-bucket-region",
		}

		for _, header := range requiredHeaders {
			found := false
			for key := range response.ResponseHeaders {
				if strings.EqualFold(key, header) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		return true
	}

	return false
}
