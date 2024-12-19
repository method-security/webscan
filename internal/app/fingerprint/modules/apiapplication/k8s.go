package apiapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type K8sLibrary struct{}

func (k8sLib *K8sLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleK8S),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	request := utils.PerformRequestScan(baseURL, parsedTargetPath, common.HttpMethodPost, common.RequestParams{}, config.Timeout)
	errors = append(errors, request.Errors...)

	finding := k8sLib.AnalyzeResponse(&request)
	if finding {
		attempt.Finding = true
	}

	attempt.Requests = []*common.RequestInfo{&request}
	return &attempt, errors
}

func (k8sLib *K8sLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.ResponseHeaders == nil {
		return false
	}

	k8sHeaders := []string{"X-Kubernetes-Pf-Flowschema-Uid", "X-Kubernetes-Pf-Prioritylevel-Uid"}

	for _, header := range k8sHeaders {
		if _, exists := response.ResponseHeaders[header]; exists {
			return true
		}
	}

	return false
}
