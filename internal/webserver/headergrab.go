package webapplication

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	webscan "github.com/Method-Security/webscan/generated/go/webserver"
	"github.com/Method-Security/webscan/utils"
)

func PerformWebserverHeadergrab(ctx context.Context, config *webscan.WebserverHeadergrabConfig) *webscan.WebserverHeadergrabReport {
	report := &webscan.WebserverHeadergrabReport{Config: config}
	errors := []string{}
	attempts := []*webscan.WebserverHeadergrabAttemptInfo{}

	for _, target := range config.Targets {
		attempt := webscan.WebserverHeadergrabAttemptInfo{Target: target}

		baseURL, parsedTargetPath, err := utils.SplitTarget(target)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		request := utils.PerformRequestScan(baseURL, parsedTargetPath, common.HttpMethodGet, common.RequestParams{}, config.Timeout)

		if request.Errors != nil {
			errors = append(errors, request.Errors...)
			attempt.Request = &request
			attempts = append(attempts, &attempt)
			continue
		}

		attempts = append(attempts, &attempt)
	}

	report.Targets = attempts
	report.Errors = errors
	return report
}
