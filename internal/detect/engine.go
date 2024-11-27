package detect

import (
	"context"
	"fmt"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
	apiapplication "github.com/Method-Security/webscan/internal/detect/modules/apiapplication"
	"github.com/Method-Security/webscan/internal/detect/modules/cloudbucket"
)

type Module interface {
	ModuleRun(target string, config *webscan.DetectConfig) (*webscan.DetectAttempt, []string)
	AnalyzeResponse(response *webscan.DetectResponseInfo) bool
}

type Engine struct {
	Library Module
	Config  *webscan.DetectConfig
	Modules map[webscan.DetectResourceType]map[webscan.DetectResourceModule]Module
}

func NewEngine(config *webscan.DetectConfig) *Engine {
	return &Engine{
		Config: config,
		Modules: map[webscan.DetectResourceType]map[webscan.DetectResourceModule]Module{
			webscan.DetectResourceTypeApiapplication: {
				*webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleK8S):     &apiapplication.K8sLibrary{},
				*webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGrpc):    &apiapplication.GrpcLibrary{},
				*webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleSwagger): &apiapplication.SwaggerLibrary{},
				*webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGraphql): &apiapplication.GraphQLLibrary{},
				*webscan.NewDetectResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleFastapi): &apiapplication.FastAPILibrary{},
			},
			webscan.DetectResourceTypeCloudbucket: {
				*webscan.NewDetectResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob): &cloudbucket.AzureBlobLibrary{},
				*webscan.NewDetectResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAwss3):     &cloudbucket.AwsS3Library{},
			},
		},
	}
}

func (e *Engine) GetModules() ([]Module, error) {
	var moduleLibs []Module

	appendModules := func(resourceModules map[webscan.DetectResourceModule]Module) {
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
	case webscan.DetectResourceTypeApiapplication:
		appendModules(e.Modules[webscan.DetectResourceTypeApiapplication])
	case webscan.DetectResourceTypeCloudbucket:
		appendModules(e.Modules[webscan.DetectResourceTypeCloudbucket])
	default:
		return nil, fmt.Errorf("unsupported server type: %s", e.Config.ResourceType)
	}

	return moduleLibs, nil
}

func (e *Engine) Run(ctx context.Context, target string) (*webscan.DetectAttempt, []string) {
	attempt, errs := e.Library.ModuleRun(target, e.Config)
	return attempt, errs
}

func (e *Engine) Launch(ctx context.Context) (*webscan.DetectReport, error) {
	report := webscan.DetectReport{ResourseType: e.Config.ResourceType, Config: e.Config}
	errors := []string{}

	moduleLibs, err := e.GetModules()
	if err != nil {
		return nil, err
	}

	var resources []*webscan.DetectResourceInfo
	for _, target := range e.Config.Targets {
		var attempts []*webscan.DetectAttempt
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
			successfulAttempts := []*webscan.DetectAttempt{}
			for _, attempt := range attempts {
				if attempt.Finding {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		resource := webscan.DetectResourceInfo{Target: target, Attempts: attempts}
		resources = append(resources, &resource)
	}

	// Marshal Report
	report.Resourses = resources
	report.Errors = errors
	return &report, nil
}
