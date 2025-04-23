package fingerprint

import (
	"context"
	"fmt"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	apiapplication "github.com/Method-Security/webscan/internal/app/fingerprint/modules/apiapplication"
	cloudbucket "github.com/Method-Security/webscan/internal/app/fingerprint/modules/cloudbucket"
	contentmanagementsystem "github.com/Method-Security/webscan/internal/app/fingerprint/modules/contentmanagementsystem"
	framework "github.com/Method-Security/webscan/internal/app/fingerprint/modules/frameworks"
	k8s "github.com/Method-Security/webscan/internal/app/fingerprint/modules/k8s"
	remoteaccess "github.com/Method-Security/webscan/internal/app/fingerprint/modules/remoteaccess"
	webserver "github.com/Method-Security/webscan/internal/app/fingerprint/modules/webserver"
	"github.com/Method-Security/webscan/utils"
)

type Module interface {
	Name() *webscan.AppFingerprintResourceModule
	Paths() []string
	RequestParams() (common.HttpMethod, common.RequestParams)
	BodyIndicators() []string
	HeaderIndicators() map[string][]string
}

type Engine struct {
	Library Module
	Config  *webscan.AppFingerprintConfig
	Modules map[webscan.AppFingerprintResourceType]map[webscan.AppFingerprintResourceModule]Module
}

var followRedirects = true

func NewEngine(config *webscan.AppFingerprintConfig) *Engine {
	return &Engine{
		Config: config,
		Modules: map[webscan.AppFingerprintResourceType]map[webscan.AppFingerprintResourceModule]Module{
			webscan.AppFingerprintResourceTypeApiapplication: {
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGrpc):    &apiapplication.GrpcLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleSwagger): &apiapplication.SwaggerLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGraphql): &apiapplication.GraphQLLibrary{},
			},
			webscan.AppFingerprintResourceTypeContentmanagementsystem: {
				*webscan.NewAppFingerprintResourceModuleFromContentManagementSystemModule(webscan.ContentManagementSystemModuleWordpress): &contentmanagementsystem.WordPressLibrary{},
			},
			webscan.AppFingerprintResourceTypeCloudbucket: {
				*webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob): &cloudbucket.AzureBlobLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAwss3):     &cloudbucket.AwsS3Library{},
			},
			webscan.AppFingerprintResourceTypeFramework: {
				*webscan.NewAppFingerprintResourceModuleFromFrameworkModule(webscan.FrameworkModuleFastapi): &framework.FastAPILibrary{},
				*webscan.NewAppFingerprintResourceModuleFromFrameworkModule(webscan.FrameworkModuleNextjs):  &framework.NextJsLibrary{},
			},
			webscan.AppFingerprintResourceTypeK8S: {
				*webscan.NewAppFingerprintResourceModuleFromK8SModule(webscan.K8SModuleK8S): &k8s.KubeLibrary{},
			},
			webscan.AppFingerprintResourceTypeRemoteaccess: {
				*webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleCitrixgateway): &remoteaccess.CitrixGatewayLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleWindowsrdp):    &remoteaccess.WindowsRDPLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(webscan.RemoteAccessModuleVmwarehorizon): &remoteaccess.VMwareHorizonLibrary{},
			},
			webscan.AppFingerprintResourceTypeWebserver: {
				*webscan.NewAppFingerprintResourceModuleFromWebServerModule(webscan.WebServerModuleApache): &webserver.ApacheLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromWebServerModule(webscan.WebServerModuleNginx):  &webserver.NginxLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromWebServerModule(webscan.WebServerModuleIis):    &webserver.IISLibrary{},
			},
		},
	}
}

func (e *Engine) GetModules() ([]Module, error) {
	var moduleLibs []Module
	appendModules := func(resourceModules map[webscan.AppFingerprintResourceModule]Module) {
		if len(e.Config.Modules) == 0 {
			for _, module := range resourceModules {
				moduleLibs = append(moduleLibs, module)
			}
		} else {
			for _, moduleName := range e.Config.Modules {
				if module, exists := resourceModules[*moduleName]; exists {
					moduleLibs = append(moduleLibs, module)
				}
			}
		}
	}

	switch e.Config.ResourceType {
	case webscan.AppFingerprintResourceTypeApiapplication:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeApiapplication])
	case webscan.AppFingerprintResourceTypeContentmanagementsystem:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeContentmanagementsystem])
	case webscan.AppFingerprintResourceTypeCloudbucket:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeCloudbucket])
	case webscan.AppFingerprintResourceTypeFramework:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeFramework])
	case webscan.AppFingerprintResourceTypeK8S:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeK8S])
	case webscan.AppFingerprintResourceTypeRemoteaccess:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeRemoteaccess])
	case webscan.AppFingerprintResourceTypeWebserver:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeWebserver])
	default:
		return nil, fmt.Errorf("unsupported module type: %s", e.Config.ResourceType)
	}

	return moduleLibs, nil
}

func (e *Engine) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.StatusCode == nil {
		return false
	}

	// Anaylsis Response Headers
	if response.ResponseHeaders == nil {
		return false
	}
	headerIndicators := e.Library.HeaderIndicators()
	// Loop through response headers
	for responseHeader, responseHeaderValue := range response.ResponseHeaders {
		// Loop through header indicators
		for headerIndicator, headerIndicatorValues := range headerIndicators {
			if strings.EqualFold(responseHeader, headerIndicator) {
				if len(headerIndicatorValues) == 0 {
					return true // If empty array, the header presence alone is an indicator
				}
				// Loop through header values
				for _, headerIndicatorValue := range headerIndicatorValues {
					if strings.Contains(strings.ToLower(responseHeaderValue), strings.ToLower(headerIndicatorValue)) {
						return true
					}
				}
			}
		}
	}

	// Anaylsis Response Body
	if response.ResponseBody == nil {
		return false
	}
	bodyIndicators := e.Library.BodyIndicators()
	lowerBody := strings.ToLower(*response.ResponseBody)
	for _, indicator := range bodyIndicators {
		if strings.Contains(lowerBody, indicator) {
			return true
		}
	}

	return false
}

func (e *Engine) Run(ctx context.Context, target string, timeout int) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    e.Library.Name(),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}
	for _, path := range e.Library.Paths() {
		// Request Configuration
		fullPath := parsedTargetPath + path
		method, params := e.Library.RequestParams()

		// Perform Request
		request := utils.PerformRequestScan(baseURL, fullPath, method, params, timeout, followRedirects)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if e.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (e *Engine) Launch(ctx context.Context) (*webscan.AppFingerprintReport, error) {
	report := webscan.AppFingerprintReport{Config: e.Config}
	errors := []string{}

	moduleLibs, err := e.GetModules()
	if err != nil {
		return nil, err
	}

	var targets []*webscan.AppFingerprintTargetInfo
	for _, target := range e.Config.Targets {
		var attempts []*webscan.AppFingerprintAttemptInfo
		for _, moduleLib := range moduleLibs {
			// Set current module library in the engine
			e.Library = moduleLib

			// Marshal Attempt results
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				// Try both http and https schemes
				schemes := []string{"http://", "https://"}
				for _, scheme := range schemes {
					schemeTarget := scheme + target
					attempt, errs := e.Run(ctx, schemeTarget, e.Config.Timeout)
					attempts = append(attempts, attempt)
					errors = append(errors, errs...)
				}
			} else {
				attempt, errs := e.Run(ctx, target, e.Config.Timeout)
				attempts = append(attempts, attempt)
				errors = append(errors, errs...)
			}
		}

		if e.Config.SuccessfulOnly {
			successfulAttempts := []*webscan.AppFingerprintAttemptInfo{}
			for _, attempt := range attempts {
				if attempt.Finding {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		target := webscan.AppFingerprintTargetInfo{Target: target, Attempts: attempts}
		targets = append(targets, &target)
	}

	// Marshal Report
	report.Targets = targets
	report.Errors = errors
	return &report, nil
}
