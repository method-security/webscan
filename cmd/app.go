package cmd

import (
	"errors"
	"fmt"
	"strings"

	appFern "github.com/Method-Security/webscan/generated/go/app"
	enumerateWordpressFern "github.com/Method-Security/webscan/generated/go/app/enumerate/cms/wordpress"
	enumerateWebserverFern "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerateApiApplication "github.com/Method-Security/webscan/internal/app/enumerate/apiapplication"
	enumerateCmsWordpress "github.com/Method-Security/webscan/internal/app/enumerate/cms/wordpress"
	enumerateKube "github.com/Method-Security/webscan/internal/app/enumerate/kube"
	enumerateWebserver "github.com/Method-Security/webscan/internal/app/enumerate/webserver"
	fingerprint "github.com/Method-Security/webscan/internal/app/fingerprint"
	"github.com/Method-Security/webscan/utils"
	"github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
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
		Long:  `Perform a fingerprinting scan against a target using specified types.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Targets flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			fingerprintFile, err := cmd.Flags().GetString("fingerprint-file")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fingeprints, err := fingerprint.LoadFingerprints(fingerprintFile)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			resourceType, err := cmd.Flags().GetString("resource-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			modules, err := cmd.Flags().GetStringSlice("modules")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filteredFingerprints, err := fingerprint.FilterFingerprints(fingeprints, resourceType, modules)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successful-only")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			insecure, err := cmd.Flags().GetBool("insecure")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Request Method
			requestMethod, err := cmd.Flags().GetString("request-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
			if err != nil {
				err = fmt.Errorf("invalid request method: %s", requestMethod)
				a.OutputSignal.AddError(err)
				return
			}

			// Flags for headless browser or browserbase
			var headlessConfig *common.HeadlessConfig
			if requestMethodEnum == common.RequestMethodHeadless || requestMethodEnum == common.RequestMethodBrowserbase {
				bPath, err := cmd.Flags().GetString("headless-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig = &common.HeadlessConfig{
					PathToBrowser: &bPath,
				}
				domTime, err := cmd.Flags().GetInt("min-dom-stabalize-time")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig.MinDomStabalizeTime = domTime
			}

			// Flags for browserbase
			var browserbaseConfig *common.BrowserbaseConfig
			var browserbaseSecrets *common.BrowserbaseSecrets
			if requestMethodEnum == common.RequestMethodBrowserbase {
				// Config flags
				proxy, err := cmd.Flags().GetBool("proxy")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				countries, err := cmd.Flags().GetStringSlice("countries")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseConfig = &common.BrowserbaseConfig{
					Proxy:     &proxy,
					Countries: countries,
				}

				// Environment variables
				tokenStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "token", "BROWSERBASE_TOKEN")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				projectStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "project", "BROWSERBASE_PROJECT")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseSecrets = &common.BrowserbaseSecrets{
					Project: projectStr,
					Token:   tokenStr,
				}

			}

			config, err := newFingerprintConfig(targets, resourceType, modules, filteredFingerprints, timeout, successfulOnly, insecure, requestMethodEnum, headlessConfig, browserbaseConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := fingerprint.Launch(cmd.Context(), config, browserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}

	fingerprintCmd.Flags().StringSlice("targets", []string{}, "URL target to perform fingerprint against")
	fingerprintCmd.Flags().String("fingerprint-file", "configs/app/fingerprints.json", "Path to the fingerprint file to use for fingerprinting")
	fingerprintCmd.Flags().String("resource-type", "", "Defined resource type to fingerprint")
	fingerprintCmd.Flags().StringSlice("modules", []string{}, "Defined resource type modules to run")
	fingerprintCmd.Flags().Bool("successful-only", false, "Only show successful attempts")
	fingerprintCmd.Flags().Bool("insecure", false, "Allow insecure SSL connections and transfers")
	fingerprintCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = fingerprintCmd.MarkFlagRequired("targets")
	_ = fingerprintCmd.MarkFlagRequired("resource-type")

	appCmd.AddCommand(fingerprintCmd)

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Perform enumeration scans against a target",
		Long:  `Perform enumeration scans against a target using specified types.`,
	}

	enumerateAPIApplicationCmd := &cobra.Command{
		Use:   "apiapplication",
		Short: "Perform API application enumeration scans against a target",
		Long:  `Perform API application enumeration scans against a target.`,
	}

	enumerateGraphqlCmd := &cobra.Command{
		Use:   "graphql",
		Short: "Perform a GraphQL enumeration scan against a target",
		Long:  `Perform a GraphQL enumeration scan against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerateApiApplication.PerformAppEnumerateGraphQL(cmd.Context(), target)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateGraphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")

	_ = enumerateGraphqlCmd.MarkFlagRequired("target")

	enumerateAPIApplicationCmd.AddCommand(enumerateGraphqlCmd)

	enumerateGrpcCmd := &cobra.Command{
		Use:   "grpc",
		Short: "Perform a gRPC enumeration scan against a target",
		Long:  `Perform a gRPC enumeration scan against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerateApiApplication.PerformAppEnumerateGrpc(cmd.Context(), target)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateGrpcCmd.Flags().String("target", "", "URL target to perform gRPC enumeration against")

	_ = enumerateGrpcCmd.MarkFlagRequired("target")

	enumerateAPIApplicationCmd.AddCommand(enumerateGrpcCmd)

	enumerateSwaggerCmd := &cobra.Command{
		Use:   "swagger",
		Short: "Perform a Swagger enumeration scan against a target",
		Long:  `Perform a Swagger enumeration scan against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
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
			report := enumerateApiApplication.PerformAppEnumerateSwagger(cmd.Context(), target, timeout)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateSwaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	enumerateSwaggerCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = enumerateSwaggerCmd.MarkFlagRequired("target")

	enumerateAPIApplicationCmd.AddCommand(enumerateSwaggerCmd)
	enumerateCmd.AddCommand(enumerateAPIApplicationCmd)

	enumerateKubeCmd := &cobra.Command{
		Use:   "kube",
		Short: "Perform a Kube enumeration scan against a target",
		Long:  `Perform a Kube enumeration scan against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get config flags
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerateKube.PerformAppEnumerateK8s(cmd.Context(), target, timeout)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateKubeCmd.Flags().String("target", "", "URL target to perform K8s enumeration against")
	enumerateKubeCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = enumerateKubeCmd.MarkFlagRequired("target")

	enumerateCmd.AddCommand(enumerateKubeCmd)

	enumerateCMSCmd := &cobra.Command{
		Use:   "cms",
		Short: "Perform CMS enumeration scans against a target",
		Long:  `Perform CMS enumeration scans against a target.`,
	}

	enumerateCMSWordpressCmd := &cobra.Command{
		Use:   "wordpress",
		Short: "Perform WordPress specific enumeration scans against a target",
		Long:  `Perform WordPress specific enumeration scans against a target.`,
	}

	enumerateCMSWordpressPluginsCmd := &cobra.Command{
		Use:   "plugins",
		Short: "Attempt to enumerate WordPress plugins on a target",
		Long:  `Attempt to enumerate WordPress plugins on a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get config flags
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
			config := newEnumerateCMSWordpressPluginsConfig(targets, plugins, timeout, threads)

			// Generate report
			report := enumerateCmsWordpress.PerformAppEnumerateCMSWordpressPlugins(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform WordPress plugins enumeration against")
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins", []string{}, "WordPress plugins to try to detect")
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins-file-paths", []string{"configs/wordpress/wordpress_plugins_small.txt"}, "File paths containing common WordPress plugins to use for enumeration")
	enumerateCMSWordpressPluginsCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")
	enumerateCMSWordpressPluginsCmd.Flags().Int("threads", 0, "Number of threads to use during enumeration (default is number of CPUs)")

	_ = enumerateCMSWordpressPluginsCmd.MarkFlagRequired("targets")

	enumerateCMSWordpressCmd.AddCommand(enumerateCMSWordpressPluginsCmd)

	enumerateCMSCmd.AddCommand(enumerateCMSWordpressCmd)

	enumerateCmd.AddCommand(enumerateCMSCmd)

	enumerateWebserverCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Perform webserver enumeration scans against a target",
		Long:  `Perform webserver enumeration scans against a target.`,
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

func newFingerprintConfig(targets []string, resourceEnum string, moduleEnums []string, fingerprints *appFern.AppResourceType, timeout int, successfulOnly bool, insecure bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserbaseConfig *common.BrowserbaseConfig) (*appFern.AppFingerprintConfig, error) {
	config := &appFern.AppFingerprintConfig{
		Targets:           targets,
		ResourceType:      resourceEnum,
		Modules:           moduleEnums,
		Fingerprints:      fingerprints,
		Timeout:           timeout,
		SuccessfulOnly:    successfulOnly,
		Insecure:          insecure,
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	if config.Timeout < 1 {
		config.Timeout = 0
	}
	return config, nil
}

func newEnumerateCMSWordpressPluginsConfig(targets []string, plugins []string, timeout int, threads int) *enumerateWordpressFern.AppEnumerateWordpressPluginsConfig {
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
