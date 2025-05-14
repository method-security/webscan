package kube

import (
	// Standard
	"context"
	"fmt"

	// Generated
	enumeratekubefern "github.com/Method-Security/webscan/generated/go/app/enumerate/kube"
	common "github.com/Method-Security/webscan/generated/go/common"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

var commonKubepaths = []string{"/api", "/livez", "/version"}

func createRequestConfig(baseURL, path string, timeout int) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    false,
		MaxRedirects:       nil,
		Insecure:           true,
		Timeout:            timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

func PerformAppEnumerateKube(ctx context.Context, target string, timeout int) *enumeratekubefern.AppEnumerateKubeReport {
	report := &enumeratekubefern.AppEnumerateKubeReport{Target: target}
	var errors []string

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	attempts := []*enumeratekubefern.AppEnumerateKubeAttemptInfo{}
	for _, path := range commonKubepaths {
		attempt := enumeratekubefern.AppEnumerateKubeAttemptInfo{Path: path}
		request, err := request.SendRequest(ctx, createRequestConfig(baseURL, fmt.Sprintf("%s%s", parsedTargetPath, path), timeout))
		if err != nil {
			errors = append(errors, err.Error())
			report.Errors = errors
			return report
		}
		attempt.Request = request
		attempts = append(attempts, &attempt)
	}

	report.Attempts = attempts
	report.Errors = errors
	return report
}
