package remoteaccess

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type CitrixGatewayLibrary struct{}

func (citLib *CitrixGatewayLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleCitrixgateway)
}

func (citLib *CitrixGatewayLibrary) Paths() []string {
	paths := []string{
		"", // Root
		"/citrix",
		"/logon/logonPoint/tmindex.html",
		"/nf/auth/login.html",
		"/selfservice",
		"/vpn",
		"/vpn/index.html",
	}
	return paths
}

func (citLib *CitrixGatewayLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (citLib *CitrixGatewayLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":                          {"citrix", "netscaler"},
		"x-citrix":                        {""},
		"citrix-transactionid":            {""},
		"set-cookie":                      {"citrix_ns", "nsc_", "nsc_aaac", "nsc_tass", "nsc_aaa"},
		"x-ns-client-ip":                  {""},
		"x-ns-location":                   {""},
		"x-citrix-gateway":                {""},
		"x-transcend-version":             {""},
		"pragma":                          {"ns"},
		"cache-control":                   {"ns"},
		"nscookie":                        {""},
		"nsc_":                            {""},
		"x-citrix-application":            {""},
		"x-aaaauth":                       {""},
		"x-aaa-session":                   {""},
		"aaa-cookie":                      {""},
		"x-ns-aaa":                        {""},
		"microsoftsharepointteamservices": {"citrix sharefile"},
	}
}

func (citLib *CitrixGatewayLibrary) BodyIndicators() []string {
	return []string{
		"citrix gateway",
		"netscaler gateway",
		"citrix adc",
		"citrix_ns_id",
		"nsapimgr",
		"citrix virtual apps",
		"citrix workspace",
		"citrix access gateway",
		"citrixauthentication",
		"ctx_login_handler",
		"name=\"citrix\"",
		"name=\"netscaler\"",
		"netscaler gateway plugin",
		"netscaler aaa",
		"netscaleraaa",
		"aaa service",
		"aaa authentication",
		"aaalogin.js",
		"aaatm.js",
		"aaapage",
		"aaacookiecheck",
		"nsaaasession",
	}
}
