package cmd

import (
	// Standard
	"errors"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"
	enumeratecmsdrupalfern "github.com/Method-Security/webscan/generated/go/enumerate/cms/drupal"
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

	// Configs
	"github.com/Method-Security/webscan/configs"
	// Utils
	utils "github.com/Method-Security/webscan/utils"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

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

			// Header flag (repeated)
			headerPairs, err := cmd.Flags().GetStringArray("header")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headers := requesthelpers.ParseHeaderPairs(headerPairs)

			// Timeout flag
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Ad-hoc query flags
			query, err := cmd.Flags().GetString("query")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			variables, err := cmd.Flags().GetString("variables")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := enumerateapiapplicationfern.EnumerateGraphqlConfig{
				Target:  target,
				Headers: headers,
				Timeout: &timeout,
			}
			if query != "" {
				config.Query = &query
			}
			if variables != "" {
				config.Variables = &variables
			}

			// Generate report
			report := enumerateapiapplication.PerformAppEnumerateGraphQL(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateAPIApplicationGraphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")
	// Config Flags
	enumerateAPIApplicationGraphqlCmd.Flags().StringArray("header", []string{}, "Request headers as 'Key: Value' pairs (repeatable)")
	enumerateAPIApplicationGraphqlCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateAPIApplicationGraphqlCmd.Flags().String("query", "", "Execute this ad-hoc GraphQL query instead of schema introspection")
	enumerateAPIApplicationGraphqlCmd.Flags().String("variables", "", "JSON-encoded variables for the ad-hoc --query")

	// Mark required flags
	_ = enumerateAPIApplicationGraphqlCmd.MarkFlagRequired("target")

	// GraphQL Field Wordlist Command (fallback when introspection is disabled)
	enumerateAPIApplicationGraphqlFieldWordlistCmd := &cobra.Command{
		Use:   "field-wordlist",
		Short: "Probe GraphQL field names via wordlist fallback",
		Long:  `When GraphQL introspection is disabled, iterate over a wordlist of candidate field names and parse "Did you mean?" suggestions from error responses to confirm accessible fields.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Wordlist flag (repeatable)
			wordlist, err := cmd.Flags().GetStringArray("wordlist")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Parent type flag
			parentType, err := cmd.Flags().GetString("parent-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Batch size flag
			batchSize, err := cmd.Flags().GetInt("batch-size")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Header flag (repeated)
			headerPairs, err := cmd.Flags().GetStringArray("header")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headers := requesthelpers.ParseHeaderPairs(headerPairs)

			// Cookie flag (repeated)
			cookiePairs, err := cmd.Flags().GetStringArray("cookie")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			cookies := map[string]string{}
			for _, pair := range cookiePairs {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) == 2 {
					cookies[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}

			// Timeout flag
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Verify TLS flag
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := enumerateapiapplicationfern.EnumerateGraphqlFieldWordlistConfig{
				Target:    target,
				VerifyTls: &verifyTLS,
				Timeout:   &timeout,
				UserAgent: &userAgentPreset,
			}
			if len(wordlist) > 0 {
				config.Wordlist = wordlist
			}
			if parentType != "" {
				config.ParentType = &parentType
			}
			if batchSize > 0 {
				config.BatchSize = &batchSize
			}
			if len(headers) > 0 {
				config.Headers = headers
			}
			if len(cookies) > 0 {
				config.Cookies = cookies
			}

			// Generate report
			report := enumerateapiapplication.PerformAppEnumerateGraphQLFieldWordlist(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().String("target", "", "GraphQL endpoint URL to probe for field names")
	// Config Flags
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().StringArray("wordlist", []string{}, "Candidate field names to probe (repeatable; defaults to embedded list when empty)")
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().String("parent-type", "Query", "GraphQL parent type to record on confirmed fields (default: Query)")
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().Int("batch-size", 10, "Number of candidate field names per probe query")
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().StringArray("header", []string{}, "Request headers as 'Key: Value' pairs (repeatable)")
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().StringArray("cookie", []string{}, "Cookies as 'name=value' pairs (repeatable)")
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates")
	// User Agent Flag
	enumerateAPIApplicationGraphqlFieldWordlistCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

	// Mark required flags
	_ = enumerateAPIApplicationGraphqlFieldWordlistCmd.MarkFlagRequired("target")

	// Add field-wordlist subcommand to graphql command
	enumerateAPIApplicationGraphqlCmd.AddCommand(enumerateAPIApplicationGraphqlFieldWordlistCmd)

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

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Header flag (repeated)
			headerPairs, err := cmd.Flags().GetStringArray("header")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headers := requesthelpers.ParseHeaderPairs(headerPairs)

			// Cookie flag (repeated)
			cookiePairs, err := cmd.Flags().GetStringArray("cookie")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			cookies := requesthelpers.ParseFormDataPairs(cookiePairs)

			// Candidate spec paths flag
			candidatePaths, err := cmd.Flags().GetStringSlice("candidate-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := enumerateapiapplicationfern.EnumerateSwaggerConfig{
				Target:         target,
				Timeout:        timeout,
				UserAgent:      userAgentPreset,
				Headers:        headers,
				Cookies:        cookies,
				CandidatePaths: candidatePaths,
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
	enumerateAPIApplicationSwaggerCmd.Flags().StringArray("header", []string{}, "Request headers as 'Key: Value' pairs (repeatable)")
	enumerateAPIApplicationSwaggerCmd.Flags().StringArray("cookie", []string{}, "Cookies as 'name=value' pairs (repeatable)")
	enumerateAPIApplicationSwaggerCmd.Flags().StringSlice("candidate-paths", []string{}, "Additional spec paths to probe before built-in paths (comma-separated)")
	// User Agent Flag
	enumerateAPIApplicationSwaggerCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

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

			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(errors.New("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(errors.New("jitter must be between 0 and 100"))
				return
			}

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getEnumerateKubeConfig(target, verifyTLS, timeout, sleep, jitter, userAgentPreset)

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
	enumerateKubeCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	enumerateKubeCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// User Agent Flag
	enumerateKubeCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

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
				pluginFile := enumeratecms.GetEnumerateWordpressPluginEmbeddedPath(PluginsFileSizeEnum)
				entries, err := configs.ReadLines(pluginFile)
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

			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(errors.New("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(errors.New("jitter must be between 0 and 100"))
				return
			}

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := getEnumerateWordpressPluginsConfig(targets, plugins, PluginsFileSizeEnum, verifyTLS, timeout, sleep, jitter, threads, userAgentPreset)

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
	enumerateCMSWordpressPluginsCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	enumerateCMSWordpressPluginsCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	enumerateCMSWordpressPluginsCmd.Flags().Int("threads", 50, "Number of concurrent threads for scanning")
	// User Agent Flag
	enumerateCMSWordpressPluginsCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

	// Mark required flags
	_ = enumerateCMSWordpressPluginsCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate CMS WordPress' Command
	enumerateCMSWordpressCmd.AddCommand(enumerateCMSWordpressPluginsCmd)

	// Add Command to 'Enumerate CMS' Command
	enumerateCMSCmd.AddCommand(enumerateCMSWordpressCmd)

	// Drupal Command
	// Subcommands: modules
	enumerateCMSDrupalCmd := &cobra.Command{
		Use:   "drupal",
		Short: "Enumerate Drupal installations",
		Long:  `Discover and analyze Drupal installations, including modules and potential vulnerabilities.`,
	}

	// Drupal Modules Command
	enumerateCMSDrupalModulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "Enumerate Drupal modules",
		Long:  `Discover and analyze Drupal modules to identify installed components and potential security issues.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get config flags
			// Add manually provided modules
			modules, err := cmd.Flags().GetStringSlice("modules")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Default to using set wordlist path if no modules-file-paths are provided
			modulesFiles, err := cmd.Flags().GetStringSlice("modules-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var modulesFileSizeEnum enumeratecmsdrupalfern.ModulesFileSize
			if len(modulesFiles) > 0 {
				entries, err := utils.GetEntriesFromTXTFiles(modulesFiles)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				modules = append(modules, entries...)
				// If no modules-file-paths are provided, use the provided wordlist path (Toggled on size Default: Small)
			} else {
				modulesFileSize, err := cmd.Flags().GetString("modules-file-size")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				modulesFileSizeEnum, err = enumeratecmsdrupalfern.NewModulesFileSizeFromString(modulesFileSize)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				moduleFile := enumeratecms.GetEnumerateDrupalModuleEmbeddedPath(modulesFileSizeEnum)
				entries, err := configs.ReadLines(moduleFile)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				modules = append(modules, entries...)
			}
			// Check to ensure at least one module is provided
			if len(modules) == 0 {
				a.OutputSignal.AddError(errors.New("no modules provided"))
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

			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(errors.New("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(errors.New("jitter must be between 0 and 100"))
				return
			}

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := getEnumerateDrupalModulesConfig(targets, modules, modulesFileSizeEnum, verifyTLS, timeout, sleep, jitter, threads, userAgentPreset)

			// Generate report
			report := enumeratecms.PerformAppEnumerateCMSDrupalModules(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateCMSDrupalModulesCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform Drupal module enumeration against")
	// Config Flags
	enumerateCMSDrupalModulesCmd.Flags().StringSlice("modules", []string{}, "Specific Drupal modules to check for")
	enumerateCMSDrupalModulesCmd.Flags().StringSlice("modules-file-paths", []string{}, "Paths to files containing Drupal module lists")
	enumerateCMSDrupalModulesCmd.Flags().String("modules-file-size", string(enumeratecmsdrupalfern.ModulesFileSizeSmall), "Size of the Drupal module list to use")
	enumerateCMSDrupalModulesCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	enumerateCMSDrupalModulesCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	enumerateCMSDrupalModulesCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	enumerateCMSDrupalModulesCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	enumerateCMSDrupalModulesCmd.Flags().Int("threads", 50, "Number of concurrent threads for scanning")
	// User Agent Flag
	enumerateCMSDrupalModulesCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

	// Mark required flags
	_ = enumerateCMSDrupalModulesCmd.MarkFlagRequired("targets")

	// Add Command to 'Enumerate CMS Drupal' Command
	enumerateCMSDrupalCmd.AddCommand(enumerateCMSDrupalModulesCmd)

	// Add Command to 'Enumerate CMS' Command
	enumerateCMSCmd.AddCommand(enumerateCMSDrupalCmd)

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

			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(errors.New("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(errors.New("jitter must be between 0 and 100"))
				return
			}

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := getEnumerateGeneralRateLimitConfig(targets, maxRequests, sleep, jitter, verifyTLS, timeout, threads, userAgentPreset)

			// Generate report
			report := enumerategeneral.PerformGeneralRatelimit(cmd.Context(), &config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	enumerateGeneralRatelimitCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform rate limit enumeration against")
	// Config Flags
	enumerateGeneralRatelimitCmd.Flags().Int("max-requests", 100, "Maximum number of requests to send")
	enumerateGeneralRatelimitCmd.Flags().Int("sleep", 0, "Time window between requests in seconds")
	enumerateGeneralRatelimitCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	enumerateGeneralRatelimitCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	enumerateGeneralRatelimitCmd.Flags().Int("timeout", 5, "Timeout per request in seconds")
	enumerateGeneralRatelimitCmd.Flags().Int("threads", 100, "Number of concurrent threads for scanning")
	// User Agent Flag
	enumerateGeneralRatelimitCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

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

			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(errors.New("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(errors.New("jitter must be between 0 and 100"))
				return
			}

			// User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate config
			config := getEnumerateDockerConfig(targets, verifyTLS, timeout, sleep, jitter, threads, userAgentPreset)

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
	enumerateContainerRegistryDockerCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	enumerateContainerRegistryDockerCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	enumerateContainerRegistryDockerCmd.Flags().Int("threads", 50, "Number of concurrent manifest requests per repository")
	// User Agent Flag
	enumerateContainerRegistryDockerCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

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
func getEnumerateWordpressPluginsConfig(targets []string, plugins []string, PluginsFileSizeEnum enumeratecmswordpressfern.PluginsFileSize, verifyTLS bool, timeout int, sleep int, jitter int, threads int, userAgent common.UserAgentPreset) enumeratecmswordpressfern.EnumerateWordpressPluginsConfig {
	config := enumeratecmswordpressfern.EnumerateWordpressPluginsConfig{
		Targets:         targets,
		Plugins:         plugins,
		PluginsFileSize: &PluginsFileSizeEnum,
		VerifyTls:       verifyTLS,
		Timeout:         max(timeout, 0),
		Sleep:           max(sleep, 0),
		Jitter:          max(jitter, 0),
		Threads:         max(threads, 0),
		UserAgent:       userAgent,
	}
	return config
}

// getEnumerateKubeConfig builds the config for Kubernetes enumeration.
func getEnumerateKubeConfig(target string, verifyTLS bool, timeout int, sleep int, jitter int, userAgent common.UserAgentPreset) enumeratekubefern.EnumerateKubeConfig {
	config := enumeratekubefern.EnumerateKubeConfig{
		Target:    target,
		VerifyTls: verifyTLS,
		Timeout:   max(timeout, 0),
		Sleep:     max(sleep, 0),
		Jitter:    max(jitter, 0),
		UserAgent: userAgent,
	}
	return config
}

// getEnumerateGeneralRateLimitConfig builds the config for general rate limit enumeration.
func getEnumerateGeneralRateLimitConfig(targets []string, maxRequests int, sleep int, jitter int, verifyTLS bool, timeout int, threads int, userAgent common.UserAgentPreset) enumerategeneralfern.EnumerateRateLimitConfig {
	config := enumerategeneralfern.EnumerateRateLimitConfig{
		Targets:     targets,
		MaxRequests: maxRequests,
		Sleep:       max(sleep, 0),
		Jitter:      max(jitter, 0),
		VerifyTls:   verifyTLS,
		Timeout:     max(timeout, 0),
		Threads:     max(threads, 0),
		UserAgent:   userAgent,
	}
	return config
}

// getEnumerateDockerConfig builds the config for Docker registry enumeration.
func getEnumerateDockerConfig(targets []string, verifyTLS bool, timeout int, sleep int, jitter int, threads int, userAgent common.UserAgentPreset) enumeratedockerfern.EnumerateDockerConfig {
	config := enumeratedockerfern.EnumerateDockerConfig{
		Targets:   targets,
		VerifyTls: verifyTLS,
		Timeout:   max(timeout, 0),
		Sleep:     max(sleep, 0),
		Jitter:    max(jitter, 0),
		Threads:   max(threads, 1),
		UserAgent: userAgent,
	}
	return config
}

// getEnumerateDrupalModulesConfig builds the config for Drupal module enumeration.
func getEnumerateDrupalModulesConfig(targets []string, modules []string, modulesFileSizeEnum enumeratecmsdrupalfern.ModulesFileSize, verifyTLS bool, timeout int, sleep int, jitter int, threads int, userAgent common.UserAgentPreset) enumeratecmsdrupalfern.EnumerateDrupalModulesConfig {
	config := enumeratecmsdrupalfern.EnumerateDrupalModulesConfig{
		Targets:         targets,
		Modules:         modules,
		ModulesFileSize: &modulesFileSizeEnum,
		VerifyTls:       verifyTLS,
		Timeout:         max(timeout, 0),
		Sleep:           max(sleep, 0),
		Jitter:          max(jitter, 0),
		Threads:         max(threads, 0),
		UserAgent:       userAgent,
	}
	return config
}
