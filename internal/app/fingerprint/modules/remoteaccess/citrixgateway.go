package remoteaccess

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type CitrixGatewayLibrary struct{}

var citrixGatewayPaths = []string{
	"", // Root
	"/citrix/",
	"/logon/logonPoint/tmindex.html",
	"/nf/auth/login.html",
	"/selfservice",
	"/vpn",
	"/vpn/index.html",
}

func (citLib *CitrixGatewayLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleCitrixgateway),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}

	for _, path := range citrixGatewayPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if citLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (citLib *CitrixGatewayLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseHeaders == nil {
		return false
	}

	// Check headers for Citrix indicators
	headerIndicators := map[string][]string{
		"Server":                          {"citrix", "netscaler"},
		"X-Citrix":                        {""},
		"Citrix-TransactionID":            {""},
		"Set-Cookie":                      {"citrix_ns", "NSC_", "NSC_AAAC", "NSC_TASS", "NSC_AAA"},
		"X-NS-Client-IP":                  {""},
		"X-NS-Location":                   {""},
		"X-Citrix-Gateway":                {""},
		"X-Transcend-Version":             {""},
		"Pragma":                          {"NS"},
		"Cache-Control":                   {"NS"},
		"NsCookie":                        {""},
		"NSC_":                            {""},
		"X-Citrix-Application":            {""},
		"X-AAAAuth":                       {""},
		"X-AAA-Session":                   {""},
		"AAA-Cookie":                      {""},
		"X-NS-AAA":                        {""},
		"MicrosoftSharePointTeamServices": {"Citrix ShareFile"},
	}

	for headerKey, values := range headerIndicators {
		if headerValue, ok := response.ResponseHeaders[headerKey]; ok {
			headerValueLower := strings.ToLower(headerValue)
			if len(values) == 0 { // If empty array, the header presence alone is an indicator
				return true
			}
			for _, value := range values {
				if strings.Contains(headerValueLower, strings.ToLower(value)) {
					return true
				}
			}
		}
	}

	if response.ResponseBody == nil {
		return false
	}

	// Check body for Citrix Gateway indicators
	citrixBodyIndicators := []string{
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

	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range citrixBodyIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}
