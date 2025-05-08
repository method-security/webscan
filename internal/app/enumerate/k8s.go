package enumerate

import (
	"context"

	webscan "github.com/Method-Security/webscan/generated/go/app/enumerate"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

var commonK8spaths = []string{"/api", "/livez", "/version"}

func PerformAppEnumerateK8s(ctx context.Context, target string, timeout int) *webscan.AppEnumerateK8SReport {
	report := &webscan.AppEnumerateK8SReport{Target: target}
	var errors []string

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	attempts := []*webscan.AppEnumerateK8SAttemptInfo{}
	for _, path := range commonK8spaths {
		attempt := webscan.AppEnumerateK8SAttemptInfo{Path: path}
		request := utils.PerformRequestScan(utils.RequestOptions{
			BaseURL:         baseURL,
			Path:            parsedTargetPath + path,
			Method:          common.HttpMethodGet,
			Params:          common.RequestParams{},
			Timeout:         timeout,
			FollowRedirects: false,
			Insecure:        true,
		})
		if request.Errors != nil {
			errors = append(errors, request.Errors...)
			attempt.Request = &request
			attempts = append(attempts, &attempt)
			continue
		}

		attempt.Request = &request
		attempts = append(attempts, &attempt)
	}

	report.Attempts = attempts
	report.Errors = errors
	return report
}
