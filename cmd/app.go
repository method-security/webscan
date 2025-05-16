package cmd

import (
	// Standard
	"errors"
	"fmt"

	// Generated
	appFern "github.com/Method-Security/webscan/generated/go/app"
	enumerateCmsWordpressFern "github.com/Method-Security/webscan/generated/go/app/enumerate/cms/wordpress"
	enumerateWebserverFern "github.com/Method-Security/webscan/generated/go/app/enumerate/webserver"

	// Internal
	enumerateApiApplication "github.com/Method-Security/webscan/internal/app/enumerate/apiapplication"
	enumerateCmsWordpress "github.com/Method-Security/webscan/internal/app/enumerate/cms/wordpress"
	enumerateKube "github.com/Method-Security/webscan/internal/app/enumerate/kube"
	enumerateWebserver "github.com/Method-Security/webscan/internal/app/enumerate/webserver"
	fingerprint "github.com/Method-Security/webscan/internal/app/fingerprint"

	// Utils
	utils "github.com/Method-Security/webscan/utils"

	// External
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

			// Create config
			config, err := newFingerprintConfig(targets, resourceType, modules, filteredFingerprints, successfulOnly, insecure, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report, err := fingerprint.Launch(cmd.Context(), config)
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
		Use:   "api-application",
		Short: "Perform API application enumeration scans against a target",
		Long:  `Perform API application enumeration scans against a target.`,
	}

	enumerateAPIApplicationGraphqlCmd := &cobra.Command{
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

	enumerateAPIApplicationGraphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")

	_ = enumerateAPIApplicationGraphqlCmd.MarkFlagRequired("target")

	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationGraphqlCmd)

	enumerateAPIApplicationGrpcCmd := &cobra.Command{
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

	enumerateAPIApplicationGrpcCmd.Flags().String("target", "", "URL target to perform gRPC enumeration against")

	_ = enumerateAPIApplicationGrpcCmd.MarkFlagRequired("target")

	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationGrpcCmd)

	enumerateAPIApplicationSwaggerCmd := &cobra.Command{
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

	enumerateAPIApplicationSwaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	enumerateAPIApplicationSwaggerCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = enumerateAPIApplicationSwaggerCmd.MarkFlagRequired("target")

	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationSwaggerCmd)
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
			report := enumerateKube.PerformAppEnumerateKube(cmd.Context(), target, timeout)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateKubeCmd.Flags().String("target", "", "URL target to perform Kube enumeration against")
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
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
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
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins-file-paths", []string{"configs/cms/wordpress/plugins_small.txt"}, "File paths containing common WordPress plugins to use for enumeration")
	enumerateCMSWordpressPluginsCmd.Flags().Int("threads", 0, "Number of threads to use during enumeration (default is number of CPUs)")
	enumerateCMSWordpressPluginsCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

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

			// Config flags
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
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

func newFingerprintConfig(targets []string, resource string, moduleEnums []string, fingerprints *appFern.AppResourceType, successfulOnly bool, insecure bool, timeout int) (*appFern.AppFingerprintConfig, error) {
	resourceEnum, err := appFern.NewAppFingerprintResourceTypeFromString(resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resource)
	}

	config := &appFern.AppFingerprintConfig{
		Targets:        targets,
		ResourceType:   resourceEnum,
		Modules:        moduleEnums,
		Fingerprints:   fingerprints,
		SuccessfulOnly: successfulOnly,
		Insecure:       insecure,
		Timeout:        max(timeout, 0),
	}
	return config, nil
}

func newEnumerateCMSWordpressPluginsConfig(targets []string, plugins []string, timeout int, threads int) *enumerateCmsWordpressFern.AppEnumerateWordpressPluginsConfig {
	config := &enumerateCmsWordpressFern.AppEnumerateWordpressPluginsConfig{
		Targets: targets,
		Plugins: plugins,
		Timeout: max(timeout, 0),
	}
	if threads > 0 {
		config.Threads = &threads
	}
	return config
}

func newEnumerateWebserverIISConfig(targets []string, threads int, timeout int) *enumerateWebserverFern.AppEnumerateIisConfig {
	config := &enumerateWebserverFern.AppEnumerateIisConfig{
		Targets: targets,
		Timeout: max(timeout, 0),
	}
	if threads > 0 {
		config.Threads = &threads
	}
	return config
}
