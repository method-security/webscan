package k8s

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type KubeLibrary struct{}

func (k8sLib *KubeLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromK8SModule(webscan.K8SModuleK8S)
}

func (k8sLib *KubeLibrary) Paths() []string {
	paths := []string{
		"", // Root
	}
	return paths
}

func (k8sLib *KubeLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (k8sLib *KubeLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"x-kubernetes-pf-flowschema-uid":    {""},
		"x-kubernetes-pf-prioritylevel-uid": {""},
	}
}

func (k8sLib *KubeLibrary) BodyIndicators() []string {
	return []string{}
}
