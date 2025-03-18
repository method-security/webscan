package remoteaccess

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type VMwareHorizonLibrary struct{}

var horizonPaths = []string{
	"", // Root
	"/broker/xml",
	"/portal",
	"/admin",
	"/view-client",
}

func (vmwLib *VMwareHorizonLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleVmwarehorizon),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}

	for _, path := range horizonPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodGet, common.RequestParams{}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if vmwLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (vmwLib *VMwareHorizonLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil || response.ResponseHeaders == nil {
		return false
	}

	// Check headers for VMware Horizon indicators
	headerIndicators := map[string][]string{
		"Server":              {"vmware", "horizon"},
		"X-VMWARE-CSRF-TOKEN": {""},
		"X-VMWARE":            {""},
		"Set-Cookie":          {"blastsession"},
		"X-Blast":             {""},
	}

	for headerKey, values := range headerIndicators {
		if headerValue, ok := response.ResponseHeaders[headerKey]; ok {
			headerValueLower := strings.ToLower(headerValue)
			if len(values) == 0 {
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

	// Check body for VMware Horizon indicators
	horizonBodyIndicators := []string{
		"vmware horizon",
		"horizon client",
		"vmware blast",
		"horizon connection server",
		"vmware-view",
		"vmware-blast",
		"vmware horizon html access",
		"vmware horizon view",
	}

	body := strings.ToLower(*response.ResponseBody)
	for _, indicator := range horizonBodyIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}
