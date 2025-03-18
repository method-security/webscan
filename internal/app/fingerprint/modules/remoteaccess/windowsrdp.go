package remoteaccess

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type WindowsRDPLibrary struct{}

var rdpPaths = []string{
	"", // Root path
	"/rdweb/",
	"/rds/",
	"/RDWeb/Pages/",
	"/RDWeb/Pages/en-US/Default.aspx",
	"/RDWeb/Pages/en-US/login.aspx",
	"/Remote/logon.aspx",
}

func (rdpLib *WindowsRDPLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleWindowsrdp),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}

	for _, path := range rdpPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if rdpLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (rdpLib *WindowsRDPLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseHeaders == nil {
		return false
	}

	// Check headers for RDP Web Access indicators
	headerIndicators := map[string][]string{
		"Server":           {"rdweb", "rdgateway"},
		"X-Powered-By":     {"rdweb"},
		"X-RDWeb-Version":  {""},
		"X-RDS-Version":    {""},
		"X-MS-RDP":         {""},
		"Set-Cookie":       {"RDPCookie", "RDP_FX_", "RDWebCookie"},
		"X-RDWebStartMode": {""},
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

	// Check if standard RDP port is open (this would require a TCP scan, not covered in this HTTP scanner)
	// Here we're only checking web interfaces

	if response.ResponseBody == nil {
		return false
	}

	// Check body for RDP Gateway indicators
	rdpBodyIndicators := []string{
		"Remote Desktop Gateway",
		"RD Gateway",
		"RD Web Access",
		"Remote Desktop Services",
		"RDWeb/Pages",
		"rdpclientlauncher",
		"msrdpclient",
		"rdp.rdp",
		"rdpcore.js",
		"RDS WebFeed",
	}

	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range rdpBodyIndicators {
		if strings.Contains(body, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}
