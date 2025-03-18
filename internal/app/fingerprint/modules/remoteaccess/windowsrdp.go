package remoteaccess

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type WindowsRDPLibrary struct{}

func (rdpLib *WindowsRDPLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleWindowsrdp)
}

func (rdpLib *WindowsRDPLibrary) Paths() []string {
	paths := []string{
		"", // Root path
		"/rdweb",
		"/rds",
		"/rdweb/pages",
		"/rdweb/pages/default.aspx",
		"/rdweb/pages/login.aspx",
		"/remote/logon.aspx",
	}
	return paths
}

func (rdpLib *WindowsRDPLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (rdpLib *WindowsRDPLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":           {"rdweb", "rdgateway"},
		"x-powered-by":     {"rdweb"},
		"x-rdweb-version":  {""},
		"x-rds-version":    {""},
		"x-ms-rdp":         {""},
		"set-cookie":       {"rdpcookie", "rdp_fx_", "rdweb"},
		"x-rdwebstartmode": {""},
	}
}

func (rdpLib *WindowsRDPLibrary) BodyIndicators() []string {
	return []string{
		"remote desktop gateway",
		"rd gateway",
		"rd web access",
		"remote desktop services",
		"rdpclientlauncher",
		"msrdpclient",
		"rdp.rdp",
		"rdpcore.js",
		"rds webfeed",
	}
}
