package webserver

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type IISLibrary struct{}

func (iisLib *IISLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromWebServerModule(webscan.WebServerModuleIis)
}

func (iisLib *IISLibrary) Paths() []string {
	paths := []string{
		"", // Root
		"/aspnet_client",
		"/asp-stuff",
		"/iisstart.htm",
		"/iishelp",
		"/iisadmpwd",
		"/webadmin",
		"/Scripts",
		"/localstart.asp",
	}
	return paths
}

func (iisLib *IISLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (iisLib *IISLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":       {"Microsoft-IIS"},
		"x-powered-by": {"ASP.NET"},
	}
}

func (iisLib *IISLibrary) BodyIndicators() []string {
	return []string{}
}
