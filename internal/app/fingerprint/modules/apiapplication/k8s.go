package apiapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type K8sLibrary struct{}

func (k8sLib *K8sLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleK8S)
}

func (k8sLib *K8sLibrary) Paths() []string {
	paths := []string{
		"", // Root
	}
	return paths
}

func (k8sLib *K8sLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (k8sLib *K8sLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"x-kubernetes-pf-flowschema-uid":    {""},
		"x-kubernetes-pf-prioritylevel-uid": {""},
	}
}

func (k8sLib *K8sLibrary) BodyIndicators() []string {
	return []string{}
}
