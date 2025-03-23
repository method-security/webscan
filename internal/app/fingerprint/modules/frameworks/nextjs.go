package webapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type NextJsLibrary struct{}

func (ngLib *NextJsLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromFrameworkModule(webscan.FrameworkModuleNextjs)
}

func (ngLib *NextJsLibrary) Paths() []string {
	paths := []string{
		"", // Root
	}
	return paths
}

func (ngLib *NextJsLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (ngLib *NextJsLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"x-powered-by":   {"next.js"},
		"x-nextjs-cache": {""},
		"vary":           {"next-router"},
	}
}

func (ngLib *NextJsLibrary) BodyIndicators() []string {
	return []string{
		"/_next/static/",
	}
}
