package kube

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type Library struct{}

func (kubeLib *Library) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromKubeModule(webscan.KubeModuleKube)
}

func (kubeLib *Library) Paths() []string {
	paths := []string{
		"", // Root
	}
	return paths
}

func (kubeLib *Library) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (kubeLib *Library) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"x-kubernetes-pf-flowschema-uid":    {""},
		"x-kubernetes-pf-prioritylevel-uid": {""},
	}
}

func (kubeLib *Library) BodyIndicators() []string {
	return []string{}
}
