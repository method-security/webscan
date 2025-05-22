package cmd

import (
	// Standard
	"errors"
	// Generated
	enumeratecmswordpressfern "github.com/Method-Security/webscan/generated/go/enumerate/cms/wordpress"
	enumerategeneralfern "github.com/Method-Security/webscan/generated/go/enumerate/general"
	enumeratekubefern "github.com/Method-Security/webscan/generated/go/enumerate/kube"
	enumeratewebserverfern "github.com/Method-Security/webscan/generated/go/enumerate/webserver"

	// Internal
	enumerateapiapplication "github.com/Method-Security/webscan/internal/enumerate/apiapplication"
	enumeratecmswordpress "github.com/Method-Security/webscan/internal/enumerate/cms/wordpress"
	enumerategeneral "github.com/Method-Security/webscan/internal/enumerate/general"
	enumeratekube "github.com/Method-Security/webscan/internal/enumerate/kube"
	enumeratewebserver "github.com/Method-Security/webscan/internal/enumerate/webserver"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	// External
	cobra "github.com/spf13/cobra"
)

// InitEnumerateCommand initializes the 'enumerate' command and its subcommands for the CLI.
func (a *WebScan) InitEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Perform various enumeration scans",
		Long:  `Perform various enumeration scans to identify and analyze web application components, APIs, and security controls.`,
	}

	enumerateAPIApplicationCmd := &cobra.Command{
		Use:   "api-application",
		Short: "Enumerate API applications",
		Long:  `Discover and analyze API endpoints, documentation, and potential vulnerabilities in web APIs.`,
	}

	enumerateAPIApplicationGraphqlCmd := &cobra.Command{
		Use:   "graphql",
		Short: "Enumerate GraphQL endpoints",
		Long:  `Discover and analyze GraphQL endpoints, including introspection queries and potential security issues.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := enumerateapiapplication.PerformAppEnumerateGraphQL(cmd.Context(), target)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateAPIApplicationGraphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")

	_ = enumerateAPIApplicationGraphqlCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate API Application' Command
	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationGraphqlCmd)

	enumerateAPIApplicationSwaggerCmd := &cobra.Command{
		Use:   "swagger",
		Short: "Enumerate Swagger/OpenAPI documentation",
		Long:  `Discover and analyze Swagger/OpenAPI documentation to identify API endpoints and their specifications.`,
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
			report := enumerateapiapplication.PerformAppEnumerateSwagger(cmd.Context(), target, timeout)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateAPIApplicationSwaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	// Config Flags
	enumerateAPIApplicationSwaggerCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")

	_ = enumerateAPIApplicationSwaggerCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate API Application' Command
	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationSwaggerCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateAPIApplicationCmd)

	enumerateKubeCmd := &cobra.Command{
		Use:   "kube",
		Short: "Enumerate Kubernetes resources",
		Long:  `Discover and analyze Kubernetes resources, including pods, services, and potential security misconfigurations.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get config flags
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

			// Set Config
			config := getEnumerateKubeConfig(target, insecure, timeout)

			// Generate report
			report := enumeratekube.PerformAppEnumerateKube(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateKubeCmd.Flags().String("target", "", "URL target to perform Kubernetes enumeration against")
	// Config Flags
	enumerateKubeCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	enumerateKubeCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")

	// Mark required flags
	_ = enumerateKubeCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateKubeCmd)

	enumerateCMSCmd := &cobra.Command{
		Use:   "cms",
		Short: "Enumerate content management systems",
		Long:  `Discover and analyze content management systems, their components, and potential security issues.`,
	}

	enumerateCMSWordpressCmd := &cobra.Command{
		Use:   "wordpress",
		Short: "Enumerate WordPress installations",
		Long:  `Discover and analyze WordPress installations, including themes, plugins, and potential vulnerabilities.`,
	}

	enumerateCMSWordpressPluginsCmd := &cobra.Command{
		Use:   "plugins",
		Short: "Enumerate WordPress plugins",
		Long:  `Discover and analyze WordPress plugins to identify installed components and potential security issues.`,
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
				entries, err := utils.GetEntriesFromTXTFiles(pluginsFiles)
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
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := getEnumerateWordpressPluginsConfig(targets, plugins, insecure, timeout, threads)

			// Generate report
			report := enumeratecmswordpress.PerformAppEnumerateCMSWordpressPlugins(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform WordPress plugin enumeration against")
	// Config Flags
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins", []string{}, "Specific WordPress plugins to check for")
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins-file-paths", []string{"configs/enumerate/cms/wordpress/plugins_small.txt"}, "Paths to files containing WordPress plugin lists")
	enumerateCMSWordpressPluginsCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	enumerateCMSWordpressPluginsCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateCMSWordpressPluginsCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")

	// Mark required flags
	_ = enumerateCMSWordpressPluginsCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate CMS WordPress' Command
	enumerateCMSWordpressCmd.AddCommand(enumerateCMSWordpressPluginsCmd)

	// Add Command to 'Enumerate CMS' Command
	enumerateCMSCmd.AddCommand(enumerateCMSWordpressCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateCMSCmd)

	enumerateWebserverCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Enumerate web servers",
		Long:  `Discover and analyze web server configurations, versions, and potential security misconfigurations.`,
	}

	enumerateWebserverIISCmd := &cobra.Command{
		Use:   "iis",
		Short: "Enumerate IIS servers",
		Long:  `Discover and analyze IIS server configurations, features, and potential security vulnerabilities.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
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
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := getEnumerateWebserverIISConfig(targets, insecure, timeout, threads)

			// Generate report
			report := enumeratewebserver.PerformAppEnumerateWebserverIIS(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateWebserverIISCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform IIS enumeration against")
	// Config Flags
	enumerateWebserverIISCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	enumerateWebserverIISCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateWebserverIISCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")

	_ = enumerateWebserverIISCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate Webserver' Command
	enumerateWebserverCmd.AddCommand(enumerateWebserverIISCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateWebserverCmd)

	enumerateGeneralCmd := &cobra.Command{
		Use:   "general",
		Short: "Perform general enumeration",
		Long:  `Perform general enumeration tasks to identify security controls and potential vulnerabilities.`,
	}

	enumerateGeneralRatelimitCmd := &cobra.Command{
		Use:   "ratelimit",
		Short: "Enumerate rate limiting controls",
		Long:  `Analyze and test rate limiting controls to identify potential bypasses or misconfigurations.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			maxRequests, err := cmd.Flags().GetInt("max-requests")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timespan, err := cmd.Flags().GetInt("timespan")
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

			// Generate config
			config := getEnumerateGeneralRateLimitConfig(targets, maxRequests, timespan, insecure, timeout)

			// Generate report
			report := enumerategeneral.PerformGeneralRatelimit(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateGeneralRatelimitCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform rate limit enumeration against")
	// Config Flags
	enumerateGeneralRatelimitCmd.Flags().Int("max-requests", 10, "Maximum number of requests to send")
	enumerateGeneralRatelimitCmd.Flags().Int("timespan", 10, "Time window for rate limit testing in seconds")
	enumerateGeneralRatelimitCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	enumerateGeneralRatelimitCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")

	_ = enumerateGeneralRatelimitCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate General' Command
	enumerateGeneralCmd.AddCommand(enumerateGeneralRatelimitCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateGeneralCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(enumerateCmd)
}

// getEnumerateWordpressPluginsConfig builds the config for WordPress plugin enumeration.
func getEnumerateWordpressPluginsConfig(targets []string, plugins []string, insecure bool, timeout int, threads int) *enumeratecmswordpressfern.EnumerateWordpressPluginsConfig {
	config := &enumeratecmswordpressfern.EnumerateWordpressPluginsConfig{
		Targets:  targets,
		Plugins:  plugins,
		Insecure: insecure,
		Timeout:  max(timeout, 0),
		Threads:  max(threads, 0),
	}
	return config
}

// getEnumerateKubeConfig builds the config for Kubernetes enumeration.
func getEnumerateKubeConfig(target string, insecure bool, timeout int) enumeratekubefern.EnumerateKubeConfig {
	config := enumeratekubefern.EnumerateKubeConfig{
		Target:   target,
		Insecure: insecure,
		Timeout:  max(timeout, 0),
	}
	return config
}

// getEnumerateWebserverIISConfig builds the config for IIS webserver enumeration.
func getEnumerateWebserverIISConfig(targets []string, insecure bool, timeout int, threads int) enumeratewebserverfern.EnumerateWebserverIisConfig {
	config := enumeratewebserverfern.EnumerateWebserverIisConfig{
		Targets:  targets,
		Insecure: insecure,
		Timeout:  max(timeout, 0),
		Threads:  max(threads, 0),
	}
	return config
}

// getEnumerateGeneralRateLimitConfig builds the config for general rate limit enumeration.
func getEnumerateGeneralRateLimitConfig(targets []string, maxRequests int, timespan int, insecure bool, timeout int) enumerategeneralfern.EnumerateGeneralRateLimitConfig {
	config := enumerategeneralfern.EnumerateGeneralRateLimitConfig{
		Targets:     targets,
		MaxRequests: maxRequests,
		Timespan:    max(timespan, 0),
		Insecure:    insecure,
		Timeout:     max(timeout, 0),
	}
	return config
}
