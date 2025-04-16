package cmd

import (
	"errors"
	"fmt"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	enumerateWebserverFern "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	enumerateWordpressFern "github.com/Method-Security/webscan/generated/go/app/enumerate/wordpress"
	"github.com/Method-Security/webscan/internal/app/enumerate"
	enumerateWebserver "github.com/Method-Security/webscan/internal/app/enumerate/webserver"
	enumerateWordpress "github.com/Method-Security/webscan/internal/app/enumerate/wordpress"
	fingerprint "github.com/Method-Security/webscan/internal/app/fingerprint"
	"github.com/Method-Security/webscan/utils"
	"github.com/spf13/cobra"
)

// InitAppCommand initializes the app command for the webscan CLI.
func (a *WebScan) InitAppCommand() {
	appCmd := &cobra.Command{
		Use:   "app",
		Short: "Perform various application scans",
		Long:  `Perform various application scans such as fingerprinting and enumeration`,
	}

	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Perform a fingerprinting scan against a target",
		Long: `Perform a fingerprinting scan against a target using specified types.
		
The fingerprint command identifies the type of web application running on the target URL.
It supports fingerprinting different resource types including API applications (FastAPI, Swagger, gRPC, GraphQL, K8s), and 
cloud buckets (AWSS3, AzureBlob). The command accepts a list of modules to run
for the specified resource type.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			resourceType, err := cmd.Flags().GetString("resourcetype")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			resourceTypeEnum, err := validateFingerprintResourceType(resourceType)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			modules, err := cmd.Flags().GetStringSlice("modules")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			moduleEnums, err := validateFingerprintResourseModuleSelection(*resourceTypeEnum, modules)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config, err := newFingerprintConfig(targets, *resourceTypeEnum, moduleEnums, timeout, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			engine := fingerprint.NewEngine(config)
			report, err := engine.Launch(cmd.Context())
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}

	// Flag Description Strings
	resourceTypes := strings.Join([]string{
		string(webscan.AppFingerprintResourceTypeApiapplication),
		string(webscan.AppFingerprintResourceTypeCloudbucket),
		string(webscan.AppFingerprintResourceTypeContentmanagementsystem),
		string(webscan.AppFingerprintResourceTypeFramework),
		string(webscan.AppFingerprintResourceTypeRemoteaccess),
		string(webscan.AppFingerprintResourceTypeWebserver),
	}, ", ")
	apiApplicationModules := strings.Join([]string{
		string(webscan.ApiApplicationModuleGraphql),
		string(webscan.ApiApplicationModuleGrpc),
		string(webscan.ApiApplicationModuleK8S),
		string(webscan.ApiApplicationModuleSwagger),
	}, ", ")
	contentManagementSystemModules := strings.Join([]string{
		string(webscan.ContentManagementSystemModuleWordpress),
	}, ", ")
	cloudBucketModules := strings.Join([]string{
		string(webscan.CloudBucketModuleAwss3),
		string(webscan.CloudBucketModuleAzureblob),
	}, ", ")
	frameworkModules := strings.Join([]string{
		string(webscan.FrameworkModuleFastapi),
		string(webscan.FrameworkModuleNextjs),
	}, ", ")
	remoteAccessModules := strings.Join([]string{
		string(webscan.RemoteAccessModuleCitrixgateway),
		string(webscan.RemoteAccessModuleVmwarehorizon),
		string(webscan.RemoteAccessModuleWindowsrdp),
	}, ", ")
	webServerModules := strings.Join([]string{
		string(webscan.WebServerModuleApache),
		string(webscan.WebServerModuleIis),
		string(webscan.WebServerModuleNginx),
	}, ", ")

	fingerprintCmd.Flags().StringSlice("targets", []string{}, "URL target to perform fingerprint against")
	fingerprintCmd.Flags().String("resourcetype", "", fmt.Sprintf("Resource type to fingerprint (%s)", resourceTypes))
	fingerprintCmd.Flags().StringSlice("modules", []string{}, fmt.Sprintf("Modules to run (APIApplication: %s; CloudBucket: %s; ContentManagementSystem: %s; Framework: %s; RemoteAccess: %s, WebServer: %s)", apiApplicationModules, cloudBucketModules, contentManagementSystemModules, frameworkModules, remoteAccessModules, webServerModules))
	fingerprintCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")
	fingerprintCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = fingerprintCmd.MarkFlagRequired("targets")
	_ = fingerprintCmd.MarkFlagRequired("resoursetype")

	appCmd.AddCommand(fingerprintCmd)

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Perform enumeration scans against a target",
		Long: `Perform enumeration scans against a target using specified types.
		
The enumerate command details the routes and endpoints for an API application. 
It extracts information such as available endpoints, HTTP methods, query parameters, and authentication mechanisms.`,
	}

	enumerateGraphqlCmd := &cobra.Command{
		Use:   "graphql",
		Short: "Perform a GraphQL enumeration scan against a target",
		Long: `Perform a GraphQL enumeration scan against a target.
		
This involves querying the GraphQL schema to discover available types, queries, mutations, and subscriptions, 
and extracting details about the fields and their types.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerate.PerformAppEnumerateGraphQL(cmd.Context(), target)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateGraphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")

	_ = enumerateGraphqlCmd.MarkFlagRequired("target")

	enumerateCmd.AddCommand(enumerateGraphqlCmd)

	enumerateGrpcCmd := &cobra.Command{
		Use:   "grpc",
		Short: "Perform a gRPC enumeration scan against a target",
		Long: `Perform a gRPC enumeration scan against a target.
		
This involves connecting to the gRPC server, using reflection to discover available services and methods, 
and extracting details about the methods, including their input and output types.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerate.PerformAppEnumerateGrpc(cmd.Context(), target)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateGrpcCmd.Flags().String("target", "", "URL target to perform gRPC enumeration against")

	_ = enumerateGrpcCmd.MarkFlagRequired("target")

	enumerateCmd.AddCommand(enumerateGrpcCmd)

	enumerateK8sCmd := &cobra.Command{
		Use:   "k8s",
		Short: "Perform a K8s enumeration scan against a target",
		Long:  `Perform a K8s enumeration scan against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Timeout flag
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerate.PerformAppEnumerateK8s(cmd.Context(), target, timeout)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateK8sCmd.Flags().String("target", "", "URL target to perform K8s enumeration against")
	enumerateK8sCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = enumerateK8sCmd.MarkFlagRequired("target")

	enumerateCmd.AddCommand(enumerateK8sCmd)
	enumerateSwaggerCmd := &cobra.Command{
		Use:   "swagger",
		Short: "Perform a Swagger enumeration scan against a target",
		Long: `Perform a Swagger enumeration scan against a target.
		
This involves fetching and parsing the Swagger (OpenAPI) documentation to extract details about the available endpoints, 
HTTP methods, query parameters, and authentication mechanisms.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			noSandbox, err := cmd.Flags().GetBool("no-sandbox")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerate.PerformAppEnumerateSwagger(cmd.Context(), target, noSandbox)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateSwaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	enumerateSwaggerCmd.Flags().Bool("no-sandbox", false, "Disable sandbox mode for Swagger scan")

	_ = enumerateSwaggerCmd.MarkFlagRequired("target")

	enumerateCmd.AddCommand(enumerateSwaggerCmd)

	enumerateWordpressCmd := &cobra.Command{
		Use:   "wordpress",
		Short: "Perform WordPress specific enumeration scans against a target",
		Long:  `Perform WordPress specific enumeration scans against a target.`,
	}

	enumerateWordpressPluginsCmd := &cobra.Command{
		Use:   "plugins",
		Short: "Attempt to enumerate WordPress plugins on a target",
		Long:  `Attempt to enumerate WordPress plugins on a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get common plugins
			plugins, err := cmd.Flags().GetStringSlice("plugins")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			pluginsFiles, err := cmd.Flags().GetStringSlice("plugins-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(pluginsFiles) > 0 {
				entries, err := utils.GetEntriesFromFiles(pluginsFiles)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				plugins = append(plugins, entries...)
			}
			if len(plugins) == 0 {
				a.OutputSignal.AddError(errors.New("no plugins provided"))
				return
			}

			// Config flags
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := newEnumerateWordpressPluginsConfig(targets, plugins, timeout, threads)

			// Generate report
			report := enumerateWordpress.PerformAppEnumerateWordpressPlugins(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateWordpressPluginsCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform WordPress plugins enumeration against")
	enumerateWordpressPluginsCmd.Flags().StringSlice("plugins", []string{}, "WordPress plugins to try to detect")
	enumerateWordpressPluginsCmd.Flags().StringSlice("plugins-file-paths", []string{"configs/wordpress/wordpress_plugins_small.txt"}, "File paths containing common WordPress plugins to use for enumeration")
	enumerateWordpressPluginsCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")
	enumerateWordpressPluginsCmd.Flags().Int("threads", 0, "Number of threads to use during enumeration (default is number of CPUs)")

	_ = enumerateWordpressPluginsCmd.MarkFlagRequired("targets")

	enumerateWordpressCmd.AddCommand(enumerateWordpressPluginsCmd)

	enumerateCmd.AddCommand(enumerateWordpressCmd)

	enumerateWebserverCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Perform webserver enumeration scans against a target",
		Long: `Perform webserver enumeration scans against a target.
		
The webserver command identifies and catalogs detailed information about a webserver. 
It extracts information such as server version, enabled modules, and more.`,
	}

	enumerateWebserverIISCmd := &cobra.Command{
		Use:   "iis",
		Short: "Perform IIS enumeration scans against a target",
		Long:  `Perform IIS enumeration scans against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Threads flag
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Timeout flag
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := newEnumerateWebserverIISConfig(targets, threads, timeout)

			// Generate report
			report := enumerateWebserver.PerformAppEnumerateWebserverIIS(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateWebserverIISCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform IIS enumeration against")
	enumerateWebserverIISCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")
	enumerateWebserverIISCmd.Flags().Int("threads", 0, "Number of threads to use during enumeration (default is number of CPUs)")

	_ = enumerateWebserverIISCmd.MarkFlagRequired("targets")

	enumerateWebserverCmd.AddCommand(enumerateWebserverIISCmd)

	enumerateCmd.AddCommand(enumerateWebserverCmd)

	appCmd.AddCommand(enumerateCmd)

	a.RootCmd.AddCommand(appCmd)
}

func validateFingerprintResourceType(resourceType string) (*webscan.AppFingerprintResourceType, error) {
	resourceTypeEnum, err := webscan.NewAppFingerprintResourceTypeFromString(strings.ToUpper(resourceType))
	if err != nil {
		return nil, err
	}
	return &resourceTypeEnum, nil
}

func validateFingerprintResourseModuleSelection(resourceType webscan.AppFingerprintResourceType, modules []string) ([]*webscan.AppFingerprintResourceModule, error) {
	moduleEnums := []*webscan.AppFingerprintResourceModule{}
	if len(modules) == 0 {
		return nil, nil
	}
	if resourceType == webscan.AppFingerprintResourceTypeApiapplication {
		for _, module := range modules {
			moduleName, err := webscan.NewApiApplicationModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}
	} else if resourceType == webscan.AppFingerprintResourceTypeCloudbucket {
		for _, module := range modules {
			moduleName, err := webscan.NewCloudBucketModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}
	} else if resourceType == webscan.AppFingerprintResourceTypeContentmanagementsystem {
		for _, module := range modules {
			moduleName, err := webscan.NewContentManagementSystemModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := webscan.NewAppFingerprintResourceModuleFromContentManagementSystemModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}

	} else if resourceType == webscan.AppFingerprintResourceTypeFramework {
		for _, module := range modules {
			moduleName, err := webscan.NewFrameworkModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := webscan.NewAppFingerprintResourceModuleFromFrameworkModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}
	} else if resourceType == webscan.AppFingerprintResourceTypeRemoteaccess {
		for _, module := range modules {
			moduleName, err := webscan.NewRemoteAccessModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := webscan.NewAppFingerprintResourceModuleFromRemoteAccessModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}
	} else if resourceType == webscan.AppFingerprintResourceTypeWebserver {
		for _, module := range modules {
			moduleName, err := webscan.NewWebServerModuleFromString(strings.ToUpper(module))
			if err != nil {
				return nil, err
			}
			moduleEnum := webscan.NewAppFingerprintResourceModuleFromWebServerModule(moduleName)
			moduleEnums = append(moduleEnums, moduleEnum)
		}
	}
	return moduleEnums, nil
}

func newFingerprintConfig(targets []string, resourceEnum webscan.AppFingerprintResourceType, moduleEnums []*webscan.AppFingerprintResourceModule, timeout int, successfulOnly bool) (*webscan.AppFingerprintConfig, error) {
	config := &webscan.AppFingerprintConfig{
		Targets:        targets,
		ResourceType:   resourceEnum,
		Modules:        moduleEnums,
		Timeout:        timeout,
		SuccessfulOnly: successfulOnly,
	}
	if config.Timeout < 1 {
		config.Timeout = 0
	}
	return config, nil
}

func newEnumerateWordpressPluginsConfig(targets []string, plugins []string, timeout int, threads int) *enumerateWordpressFern.AppEnumerateWordpressPluginsConfig {
	config := &enumerateWordpressFern.AppEnumerateWordpressPluginsConfig{
		Targets: targets,
		Plugins: plugins,
		Timeout: timeout,
	}

	if threads > 0 {
		config.Threads = &threads
	}
	return config
}

func newEnumerateWebserverIISConfig(targets []string, threads int, timeout int) *enumerateWebserverFern.AppEnumerateIisConfig {
	config := &enumerateWebserverFern.AppEnumerateIisConfig{
		Targets: targets,
		Timeout: timeout,
	}

	if threads > 0 {
		config.Threads = &threads
	}

	return config
}
