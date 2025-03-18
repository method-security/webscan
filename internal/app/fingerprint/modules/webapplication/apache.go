package webapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type ApacheLibrary struct{}

func (apLib *ApacheLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromWebApplicationModule(webscan.WebApplicationModuleApache)
}

func (apLib *ApacheLibrary) Paths() []string {
	paths := []string{
		"", // Root
		"/server-status",
		"/icons",
		"/manual",
		"/cgi-bin",
		"/.htaccess",
	}
	return paths
}

func (apLib *ApacheLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (apLib *ApacheLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":       {"apache"},
		"x-powered-by": {""},
	}
}

func (apLib *ApacheLibrary) BodyIndicators() []string {
	return []string{
		"<address>apache",
		"apache server at",
		"powered by apache",
		"apache/",
		"<title>apache http server",
		"<title>apache status</title>",
		"apache tomcat",
	}
}
