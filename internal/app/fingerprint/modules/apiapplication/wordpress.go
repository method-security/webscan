package apiapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type WordPressLibrary struct{}

func (wpLib *WordPressLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleWordpress)
}

func (wpLib *WordPressLibrary) Paths() []string {
	paths := []string{
		"", // Root
		"/wp-login.php",
		"/wp-admin",
		"/xmlrpc.php",
		"/wp-content",
		"/wp-includes",
	}
	return paths
}

func (wpLib *WordPressLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (wpLib *WordPressLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"x-pingback":   {"wp-json", "wp engine", "wordpress"},
		"link":         {"wp-json", "wp engine", "wordpress"},
		"x-powered-by": {"wp-json", "wp engine", "wordpress"},
		"server":       {"wordpress", "wordpress/nginx"},
	}
}

func (wpLib *WordPressLibrary) BodyIndicators() []string {
	return []string{
		"wp-content/", "wp-includes/", "<meta name=\"generator\" content=\"WordPress", "/wp-json", "/wp-admin/admin-ajax.php",
	}
}
