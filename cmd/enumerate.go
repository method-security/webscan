package cmd

import (
	// Standard
	"errors"
	// Generated
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
	enumeratecmswordpressfern "github.com/Method-Security/webscan/generated/go/enumerate/cms/wordpress"
	enumeratedockerfern "github.com/Method-Security/webscan/generated/go/enumerate/containerregistry"
	enumerategeneralfern "github.com/Method-Security/webscan/generated/go/enumerate/general"
	enumeratekubefern "github.com/Method-Security/webscan/generated/go/enumerate/kube"

	// Internal
	enumerateapiapplication "github.com/Method-Security/webscan/internal/enumerate/apiapplication"
	enumeratecms "github.com/Method-Security/webscan/internal/enumerate/cms"
	enumeratedocker "github.com/Method-Security/webscan/internal/enumerate/containerregistry"
	enumerategeneral "github.com/Method-Security/webscan/internal/enumerate/general"
	enumeratekube "github.com/Method-Security/webscan/internal/enumerate/kube"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	// External
	cobra "github.com/spf13/cobra"
)

// InitEnumerateCommand initializes the 'enumerate' command and its subcommands for the CLI.
func (a *WebScan) InitEnumerateCommand() {

	// Enumerate Command
	// Subcommands: api-application, cms, kube, webserver, general
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Perform various enumeration scans",
		Long:  `Perform various enumeration scans to identify and analyze web application components, APIs, and security controls.`,
	}

	// API Application Command
	// Subcommands: graphql, swagger
	enumerateAPIApplicationCmd := &cobra.Command{
		Use:   "api-application",
		Short: "Enumerate API applications",
		Long:  `Discover and analyze API endpoints, documentation, and potential vulnerabilities in web APIs.`,
	}

	// GraphQL Command
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

			config := enumerateapiapplicationfern.EnumerateGraphqlConfig{
				Target: target,
			}

			// Generate report
			report := enumerateapiapplication.PerformAppEnumerateGraphQL(cmd.Context(), config.Target)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateAPIApplicationGraphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")

	// Mark required flags
	_ = enumerateAPIApplicationGraphqlCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate API Application' Command
	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationGraphqlCmd)

	// Swagger Command
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

			// Headless path flag
			headlessPath, err := cmd.Flags().GetString("headless-path")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := enumerateapiapplicationfern.EnumerateSwaggerConfig{
				Target:  target,
				Timeout: timeout,
			}

			// Generate report
			report := enumerateapiapplication.PerformAppEnumerateSwagger(cmd.Context(), config, headlessPath)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateAPIApplicationSwaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	// Config Flags
	enumerateAPIApplicationSwaggerCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateAPIApplicationSwaggerCmd.Flags().String("headless-path", "", "Path to headless browser executable")

	_ = enumerateAPIApplicationSwaggerCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate API Application' Command
	enumerateAPIApplicationCmd.AddCommand(enumerateAPIApplicationSwaggerCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateAPIApplicationCmd)

	// Kube Command
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
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
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
			config := getEnumerateKubeConfig(target, verifyTLS, timeout)

			// Generate report
			report := enumeratekube.PerformAppEnumerateKube(cmd.Context(), &config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateKubeCmd.Flags().String("target", "", "URL target to perform Kubernetes enumeration against")
	// Config Flags
	enumerateKubeCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	enumerateKubeCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")

	// Mark required flags
	_ = enumerateKubeCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateKubeCmd)

	// CMS Command
	// Subcommands: wordpress
	enumerateCMSCmd := &cobra.Command{
		Use:   "cms",
		Short: "Enumerate content management systems",
		Long:  `Discover and analyze content management systems, their components, and potential security issues.`,
	}

	// WordPress Command
	// Subcommands: plugins
	enumerateCMSWordpressCmd := &cobra.Command{
		Use:   "wordpress",
		Short: "Enumerate WordPress installations",
		Long:  `Discover and analyze WordPress installations, including themes, plugins, and potential vulnerabilities.`,
	}

	// WordPress Plugins Command
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
			// Add manually provided plugins
			plugins, err := cmd.Flags().GetStringSlice("plugins")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Default to using set wordlist path if no plugins-file-paths are provided
			pluginsFiles, err := cmd.Flags().GetStringSlice("plugins-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var PluginsFileSizeEnum enumeratecmswordpressfern.PluginsFileSize
			if len(pluginsFiles) > 0 {
				entries, err := utils.GetEntriesFromTXTFiles(pluginsFiles)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				plugins = append(plugins, entries...)
				// If no plugins-file-paths are provided, use the provided wordlist path (Toggled on size Default: Small)
			} else {
				PluginsFileSize, err := cmd.Flags().GetString("plugins-file-size")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				PluginsFileSizeEnum, err = enumeratecmswordpressfern.NewPluginsFileSizeFromString(PluginsFileSize)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				pluginFile := enumeratecms.GetEnumerateWordpressPluginWordlistPath(PluginsFileSizeEnum)
				entries, err := utils.GetEntriesFromTXTFiles([]string{pluginFile})
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				plugins = append(plugins, entries...)
			}
			// Check to ensure at least one plugin is provided
			if len(plugins) == 0 {
				a.OutputSignal.AddError(errors.New("no plugins provided"))
				return
			}
			// Other config flags
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
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
			config := getEnumerateWordpressPluginsConfig(targets, plugins, PluginsFileSizeEnum, verifyTLS, timeout, threads)

			// Generate report
			report := enumeratecms.PerformAppEnumerateCMSWordpressPlugins(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform WordPress plugin enumeration against")
	// Config Flags
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins", []string{}, "Specific WordPress plugins to check for")
	enumerateCMSWordpressPluginsCmd.Flags().StringSlice("plugins-file-paths", []string{}, "Paths to files containing WordPress plugin lists")
	enumerateCMSWordpressPluginsCmd.Flags().String("plugins-file-size", "SMALL", "Size of the WordPress plugin list to use")
	enumerateCMSWordpressPluginsCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
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

	// General Command
	// Subcommands: ratelimit
	enumerateGeneralCmd := &cobra.Command{
		Use:   "general",
		Short: "Perform general enumeration",
		Long:  `Perform general enumeration tasks to identify security controls and potential vulnerabilities.`,
	}

	// Rate Limit Command
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
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
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
			config := getEnumerateGeneralRateLimitConfig(targets, maxRequests, sleep, verifyTLS, timeout, threads)

			// Generate report
			report := enumerategeneral.PerformGeneralRatelimit(cmd.Context(), &config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateGeneralRatelimitCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform rate limit enumeration against")
	// Config Flags
	enumerateGeneralRatelimitCmd.Flags().Int("max-requests", 10, "Maximum number of requests to send")
	enumerateGeneralRatelimitCmd.Flags().Int("sleep", 0, "Time window between requests in seconds")
	enumerateGeneralRatelimitCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	enumerateGeneralRatelimitCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateGeneralRatelimitCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")

	// Mark required flags
	_ = enumerateGeneralRatelimitCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate General' Command
	enumerateGeneralCmd.AddCommand(enumerateGeneralRatelimitCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateGeneralCmd)

	// Container Registry Command
	// Subcommands: graphql, swagger
	enumerateContainerRegistryCmd := &cobra.Command{
		Use:   "container-registry",
		Short: "Enumerate container registries",
		Long:  `Discover and analyze container registries, including repositories, images, and their manifest data.`,
	}

	// Docker Registry Command
	enumerateContainerRegistryDockerCmd := &cobra.Command{
		Use:   "docker",
		Short: "Enumerate Docker container registries",
		Long:  `Discover and analyze Docker container registries, including repositories, images, and their manifest data.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get config flags
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
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
			config := getEnumerateDockerConfig(targets, verifyTLS, timeout, threads)

			// Generate report
			report := enumeratedocker.PerformAppEnumerateContainerRegistryDocker(cmd.Context(), &config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateContainerRegistryDockerCmd.Flags().StringSlice("targets", []string{}, "URLs of Docker Container Registries to enumerate")
	// Config Flags
	enumerateContainerRegistryDockerCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	enumerateContainerRegistryDockerCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateContainerRegistryDockerCmd.Flags().Int("threads", 25, "Number of concurrent manifest requests per repository")

	// Mark required flags
	_ = enumerateContainerRegistryDockerCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate Container Registry' Command
	enumerateContainerRegistryCmd.AddCommand(enumerateContainerRegistryDockerCmd)

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateContainerRegistryCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(enumerateCmd)
}

// getEnumerateWordpressPluginsConfig builds the config for WordPress plugin enumeration.
func getEnumerateWordpressPluginsConfig(targets []string, plugins []string, PluginsFileSizeEnum enumeratecmswordpressfern.PluginsFileSize, verifyTLS bool, timeout int, threads int) enumeratecmswordpressfern.EnumerateWordpressPluginsConfig {
	config := enumeratecmswordpressfern.EnumerateWordpressPluginsConfig{
		Targets:         targets,
		Plugins:         plugins,
		PluginsFileSize: &PluginsFileSizeEnum,
		VerifyTls:       verifyTLS,
		Timeout:         max(timeout, 0),
		Threads:         max(threads, 0),
	}
	return config
}

// getEnumerateKubeConfig builds the config for Kubernetes enumeration.
func getEnumerateKubeConfig(target string, verifyTLS bool, timeout int) enumeratekubefern.EnumerateKubeConfig {
	config := enumeratekubefern.EnumerateKubeConfig{
		Target:    target,
		VerifyTls: verifyTLS,
		Timeout:   max(timeout, 0),
	}
	return config
}

// getEnumerateGeneralRateLimitConfig builds the config for general rate limit enumeration.
func getEnumerateGeneralRateLimitConfig(targets []string, maxRequests int, sleep int, verifyTLS bool, timeout int, threads int) enumerategeneralfern.EnumerateRateLimitConfig {
	config := enumerategeneralfern.EnumerateRateLimitConfig{
		Targets:     targets,
		MaxRequests: maxRequests,
		Sleep:       max(sleep, 0),
		VerifyTls:   verifyTLS,
		Timeout:     max(timeout, 0),
		Threads:     max(threads, 0),
	}
	return config
}

// getEnumerateDockerConfig builds the config for Docker registry enumeration.
func getEnumerateDockerConfig(targets []string, verifyTLS bool, timeout int, threads int) enumeratedockerfern.EnumerateDockerConfig {
	config := enumeratedockerfern.EnumerateDockerConfig{
		Targets:   targets,
		VerifyTls: verifyTLS,
		Timeout:   max(timeout, 0),
		Threads:   max(threads, 1),
	}
	return config
}
