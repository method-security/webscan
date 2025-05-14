package kube

import (
	"context"

	enumeratekubefern "github.com/Method-Security/webscan/generated/go/app/enumerate/kube"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

var commonK8spaths = []string{"/api", "/livez", "/version"}

func createEnumerateK8sRequestConfig(baseURL, path string, timeout int) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		Timeout:            timeout,
		FollowRedirects:    false,
		MaxRedirects:       nil,
		Insecure:           true,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

func PerformAppEnumerateK8s(ctx context.Context, target string, timeout int) *enumeratekubefern.AppEnumerateKubeReport {
	report := &enumeratekubefern.AppEnumerateKubeReport{Target: target}
	var errors []string

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	attempts := []*enumeratekubefern.AppEnumerateKubeAttemptInfo{}
	for _, path := range commonK8spaths {
		attempt := enumeratekubefern.AppEnumerateKubeAttemptInfo{Path: path}
		request, err := request.SendRequest(ctx, createEnumerateK8sRequestConfig(baseURL, parsedTargetPath+path, timeout))
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
