package apiapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type SwaggerLibrary struct{}

func (swaggerLib *SwaggerLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleSwagger)
}

func (swaggerLib *SwaggerLibrary) Paths() []string {
	paths := []string{
		"/swagger-ui-bundle.js",
		"/swagger-ui.html",
		"/swagger/index.html",
		"/swagger",
		"/api-docs",
		"/v2/api-docs",
		"/swagger/v1/swagger.json",
		"/api/swagger",
		"/swagger.json",
		"/swagger.yaml",
	}
	return paths
}

func (swaggerLib *SwaggerLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (swaggerLib *SwaggerLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"x-swagger-router-basepath":   {""},
		"x-swagger-router-controller": {""},
	}
}

func (swaggerLib *SwaggerLibrary) BodyIndicators() []string {
	return []string{
		"swagger:",
		"<div id=\"swagger-ui\">",
		"\"openapi\":",
		"\"paths\":",
		"\"components\":",
		"\"info\": {\"title\":",
		"swagger ui",
		"loadswaggerui",
		"\"swagger\":",
	}
}
