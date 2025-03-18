package webapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type NginxLibrary struct{}

func (ngLib *NginxLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromWebApplicationModule(webscan.WebApplicationModuleNginx)
}

func (ngLib *NginxLibrary) Paths() []string {
	paths := []string{
		"", // Root
		"/nginx_status",
		"/status",
		"/.nginx-debian.html",
		"/50x.html",
		"/404.html",
	}
	return paths
}

func (ngLib *NginxLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (ngLib *NginxLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":       {"nginx"},
		"x-powered-by": {"nginx"},
	}
}

func (ngLib *NginxLibrary) BodyIndicators() []string {
	return []string{
		"<title>welcome to nginx</title>",
		"<title>nginx error</title>",
		"<title>test page for nginx</title>",
		"<h1>welcome to nginx!</h1>",
		"<center>nginx</center>",
		"<hr><center>nginx/",
		"powered by nginx",
	}
}
