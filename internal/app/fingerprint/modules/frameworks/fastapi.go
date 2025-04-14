package framework

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type FastAPILibrary struct{}

func (fastapiLib *FastAPILibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromFrameworkModule(webscan.FrameworkModuleFastapi)
}

func (fastapiLib *FastAPILibrary) Paths() []string {
	paths := []string{
		"/docs",
		"/redoc",
		"/openapi.json",
	}
	return paths
}

func (fastapiLib *FastAPILibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (fastapiLib *FastAPILibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server": {"fastapi"},
	}
}

func (fastapiLib *FastAPILibrary) BodyIndicators() []string {
	return []string{
		"fastapi - swagger ui",
		"fastapi - redoc",
		"fastapi.tiangolo.com",
	}
}
