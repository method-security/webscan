package cmd

import (
	// Standard
	"fmt"
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverprobe "github.com/Method-Security/webscan/internal/discover"
	discoverapplication "github.com/Method-Security/webscan/internal/discover/application"
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	// External
	cobra "github.com/spf13/cobra"
)

func (a *WebScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Perform various discovery scans",
		Long:  `Perform various discovery scans to identify web applications, routes, and static assets.`,
	}

	discoverApplicationCmd := &cobra.Command{
		Use:   "application",
		Short: "Perform application fingerprinting against targets",
		Long:  `Perform application fingerprinting to identify web technologies, frameworks, and services running on target URLs.`,
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
			fingeprints, err := discoverapplication.LoadFingerprints(fingerprintFile)
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
			filteredFingerprints, err := discoverapplication.FilterFingerprints(fingeprints, resourceType, modules)
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
			config, err := getDiscoverApplicationFingerprintConfig(targets, resourceType, modules, filteredFingerprints, successfulOnly, insecure, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report, err := discoverapplication.LaunchFingerprintEngine(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverApplicationCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform fingerprinting against")
	// Config Flags
	discoverApplicationCmd.Flags().String("fingerprint-file", "configs/discover/application/fingerprints.json", "Path to the fingerprint definitions file")
	discoverApplicationCmd.Flags().String("resource-type", "", "Type of resource to fingerprint (e.g., web, api, cms)")
	discoverApplicationCmd.Flags().StringSlice("modules", []string{}, "Specific fingerprinting modules to run")
	discoverApplicationCmd.Flags().Bool("successful-only", false, "Only show successful fingerprint matches")
	discoverApplicationCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	discoverApplicationCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")

	// Mark Required Flags
	_ = discoverApplicationCmd.MarkFlagRequired("targets")
	_ = discoverApplicationCmd.MarkFlagRequired("resource-type")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverApplicationCmd)

	discoverPageCmd := &cobra.Command{
		Use:   "page",
		Short: "Capture and analyze web pages",
		Long:  `Capture and analyze web pages to extract content, take screenshots, and perform various page-level analysis.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			maxRedirects, err := cmd.Flags().GetInt("max-redirects")
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

			// Get Request Method flag
			requestMethodConfig, err := utils.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get screenshot flag
			// Screenshot flag is not supported for headless or Browserbase capture methods
			takeScreenshot, err := cmd.Flags().GetBool("screenshot")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if takeScreenshot && (requestMethodConfig.RequestMethodEnum == common.RequestMethodStandard || requestMethodConfig.RequestMethodEnum == common.RequestMethodBrowserbase) {
				a.OutputSignal.AddError(fmt.Errorf("screenshot flag is not supported for standard or browserbase capture methods"))
				return
			}

			// Set Config
			config := getDiscoverPageConfig(target, maxRedirects, insecure, timeout, takeScreenshot, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate a report
			report := discoverpage.PerformPageCapture(cmd.Context(), config, requestMethodConfig.BrowserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverPageCmd.Flags().String("target", "", "URL target to capture and analyze")
	// Config Flags
	discoverPageCmd.Flags().Bool("screenshot", false, "Capture a screenshot of the page")
	discoverPageCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverPageCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	discoverPageCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	// Request Method Flags for all capture subcommands
	discoverPageCmd.Flags().String("request-method", "STANDARD", "Request method to use (standard, headless, browserbase)")
	discoverPageCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverPageCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time to wait for DOM stabilization in seconds")
	discoverPageCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverPageCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverPageCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverPageCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")

	// Mark Required Flags
	_ = discoverPageCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverPageCmd)

	discoverProbeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe targets for web application existence",
		Long:  `Probe target URLs to identify if they are running web applications and determine their basic characteristics.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			maxRedirects, err := cmd.Flags().GetInt("max-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			HTTPSOnly, err := cmd.Flags().GetBool("https-only")
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

			// Get Request Method flag
			requestMethodConfig, err := utils.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverProbeConfig(targets, maxRedirects, HTTPSOnly, insecure, timeout, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate report
			report, err := discoverprobe.PerformWebProbe(cmd.Context(), config, requestMethodConfig.BrowserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverProbeCmd.Flags().StringSlice("targets", []string{}, "URL targets to probe for web applications")
	// Config Flags
	discoverProbeCmd.Flags().Bool("https-only", true, "Only probe HTTPS URLs")
	discoverProbeCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverProbeCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	discoverProbeCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	// Request Method Flags
	discoverProbeCmd.Flags().String("request-method", "STANDARD", "Request method to use (standard, headless, browserbase)")
	discoverProbeCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverProbeCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time to wait for DOM stabilization in seconds")
	discoverProbeCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverProbeCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverProbeCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverProbeCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")

	// Mark Required Flags
	_ = discoverProbeCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverProbeCmd)

	discoverRouteCmd := &cobra.Command{
		Use:   "route",
		Short: "Discover and analyze web routes",
		Long:  `Discover and analyze web routes to map application structure, identify endpoints, and detect potential vulnerabilities.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config flags
			requireBaseURLMatch, err := cmd.Flags().GetBool("require-base-url-match")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ignoreStaticAssets, err := cmd.Flags().GetBool("ignore-static-assets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			spiderDepth, err := cmd.Flags().GetInt("spider-depth")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxRedirects, err := cmd.Flags().GetInt("max-redirects")
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
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Get Request Method flag
			requestMethodConfig, err := utils.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverRouteConfig(target, requireBaseURLMatch, ignoreStaticAssets, spiderDepth, maxRedirects, insecure, timeout, threads, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate a report
			report := discoverroute.PerformRouteCapture(cmd.Context(), config, requestMethodConfig.BrowserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverRouteCmd.Flags().String("target", "", "URL target to discover routes from")
	// Config Flags
	discoverRouteCmd.Flags().Bool("require-base-url-match", true, "Only scan routes sharing the target's base URL")
	discoverRouteCmd.Flags().Bool("ignore-static-assets", true, "Exclude static assets from route discovery")
	discoverRouteCmd.Flags().Int("spider-depth", 1, "Maximum depth for route spidering")
	discoverRouteCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverRouteCmd.Flags().Bool("insecure", false, "Allow insecure SSL/TLS connections")
	discoverRouteCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverRouteCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")

	// Request Method Flags
	discoverRouteCmd.Flags().String("request-method", "STANDARD", "Request method to use (standard, headless, browserbase)")
	discoverRouteCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverRouteCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time to wait for DOM stabilization in seconds")
	discoverRouteCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverRouteCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverRouteCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverRouteCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")

	// Mark Required Flags
	_ = discoverRouteCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverRouteCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

func getDiscoverApplicationFingerprintConfig(targets []string, resource string, moduleEnums []string, fingerprints *discover.ApplicationFingerprintResource, successfulOnly bool, insecure bool, timeout int) (*discover.DiscoverApplicationFingerprintConfig, error) {
	resourceEnum, err := discover.NewApplicationFingerprintResourceTypeFromString(resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resource)
	}
	config := &discover.DiscoverApplicationFingerprintConfig{
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

func getDiscoverPageConfig(target string, maxRedirects int, insecure bool, timeout int, takeScreenshot bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverPageConfig {
	config := discover.DiscoverPageConfig{
		Target:            target,
		MaxRedirects:      maxRedirects,
		Insecure:          insecure,
		Timeout:           max(timeout, 0),
		TakeScreenshot:    takeScreenshot,
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return config
}

func getDiscoverProbeConfig(targets []string, maxRedirects int, HTTPSOnly bool, insecure bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) *discover.DiscoverProbeConfig {
	config := &discover.DiscoverProbeConfig{
		Targets:           targets,
		MaxRedirects:      maxRedirects,
		HttpsOnly:         HTTPSOnly,
		Insecure:          insecure,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}

	return config
}

func getDiscoverRouteConfig(target string, requiredBaseURLMatch bool, ignoreStaticAssets bool, spiderDepth int, maxRedirects int, insecure bool, timeout int, threads int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverRouteConfig {
	config := discover.DiscoverRouteConfig{
		Target:              target,
		IgnoreStaticAssets:  ignoreStaticAssets,
		RequireBaseUrlMatch: requiredBaseURLMatch,
		SpiderDepth:         spiderDepth,
		MaxRedirects:        maxRedirects,
		Insecure:            insecure,
		Timeout:             max(timeout, 0),
		Threads:             max(threads, 0),
		RequestMethod:       requestMethod,
		HeadlessConfig:      headlessConfig,
		BrowserbaseConfig:   browserbaseConfig,
	}
	return config
}
