package remoteaccess

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type VMwareHorizonLibrary struct{}

func (vmwLib *VMwareHorizonLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleVmwarehorizon)
}

func (vmwLib *VMwareHorizonLibrary) Paths() []string {
	paths := []string{
		"", // Root
		"/broker/xml",
		"/portal",
		"/admin",
		"/view-client",
	}
	return paths
}

func (vmwLib *VMwareHorizonLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (vmwLib *VMwareHorizonLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":              {"vmware", "horizon"},
		"x-vmware-csrf-token": {""},
		"x-vmware":            {""},
		"set-cookie":          {"blastsession"},
		"x-blast":             {""},
	}
}

func (vmwLib *VMwareHorizonLibrary) BodyIndicators() []string {
	return []string{
		"vmware horizon",
		"horizon client",
		"vmware blast",
		"horizon connection server",
		"vmware-view",
		"vmware-blast",
		"vmware horizon html access",
		"vmware horizon view",
	}
}
