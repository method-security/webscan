package fingerprint

import (
	"context"
	"fmt"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	apiapplication "github.com/Method-Security/webscan/internal/app/fingerprint/modules/apiapplication"
	cloudbucket "github.com/Method-Security/webscan/internal/app/fingerprint/modules/cloudbucket"
)

type Module interface {
	ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string)
	AnalyzeResponse(request *common.RequestInfo) bool
}

type Engine struct {
	Library Module
	Config  *webscan.AppFingerprintConfig
	Modules map[webscan.AppFingerprintResourceType]map[webscan.AppFingerprintResourceModule]Module
}

func NewEngine(config *webscan.AppFingerprintConfig) *Engine {
	return &Engine{
		Config: config,
		Modules: map[webscan.AppFingerprintResourceType]map[webscan.AppFingerprintResourceModule]Module{
			webscan.AppFingerprintResourceTypeApiapplication: {
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleK8S):     &apiapplication.K8sLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGrpc):    &apiapplication.GrpcLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleSwagger): &apiapplication.SwaggerLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGraphql): &apiapplication.GraphQLLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleFastapi): &apiapplication.FastAPILibrary{},
			},
			webscan.AppFingerprintResourceTypeCloudbucket: {
				*webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob): &cloudbucket.AzureBlobLibrary{},
				*webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAwss3):     &cloudbucket.AwsS3Library{},
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
	case webscan.AppFingerprintResourceTypeCloudbucket:
		appendModules(e.Modules[webscan.AppFingerprintResourceTypeCloudbucket])
	default:
		return nil, fmt.Errorf("unsupported server type: %s", e.Config.ResourceType)
	}

	return moduleLibs, nil
}

func (e *Engine) Run(ctx context.Context, target string) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt, errs := e.Library.ModuleRun(target, e.Config)
	return attempt, errs
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
					attempt, errs := e.Run(ctx, schemeTarget)
					attempts = append(attempts, attempt)
					errors = append(errors, errs...)
				}
			} else {
				attempt, errs := e.Run(ctx, target)
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
