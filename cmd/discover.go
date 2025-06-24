package cmd

import (
	// Standard
	"errors"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverprobe "github.com/Method-Security/webscan/internal/discover"
	discoverapplication "github.com/Method-Security/webscan/internal/discover/application"
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route"
	discoversaas "github.com/Method-Security/webscan/internal/discover/saas/active"
	discoversaashelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	cobra "github.com/spf13/cobra"
)

// InitDiscoverCommand initializes the 'discover' command and its subcommands for the CLI.
func (a *WebScan) InitDiscoverCommand() {
	// Discover Command
	// Subcommands: application, page, probe, route, saas
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Perform various discovery scans",
		Long:  `Perform various discovery scans to identify web applications, routes, and static assets.`,
	}

	// Application Command
	// Subcommands: fingerprint
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
			resourceConfigType, err := getDiscoverApplicationResourceConfigTypeFromString(resourceType)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filteredFingerprints, err := discoverapplication.FilterFingerprints(fingeprints, &resourceConfigType, modules)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successful-only")
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

			// Create config
			config, err := getDiscoverApplicationConfig(targets, resourceType, modules, filteredFingerprints, successfulOnly, verifyTLS, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Generate report
			report, err := discoverapplication.LaunchFingerprintEngine(cmd.Context(), config, filteredFingerprints)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverApplicationCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform fingerprinting against")
	// Config Flags
	discoverApplicationCmd.Flags().String("resource-type", "ALL", "Type of resource to fingerprint (e.g., web, api, cms)")
	discoverApplicationCmd.Flags().StringSlice("modules", []string{}, "Specific fingerprinting modules to run")
	discoverApplicationCmd.Flags().Bool("successful-only", false, "Only show successful fingerprint matches")
	discoverApplicationCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverApplicationCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverApplicationCmd.Flags().String("fingerprint-file", "/opt/method/webscan/var/conf/discover/application/fingerprints.json", "Path to the fingerprint definitions file")

	// Mark Required Flags
	_ = discoverApplicationCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverApplicationCmd)

	// Page Command
	// Subcommands: capture
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

			// Get Request Method flag
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
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
			config := getDiscoverPageConfig(target, maxRedirects, verifyTLS, timeout, takeScreenshot, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

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
	discoverPageCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
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

	// Probe Command
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

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverProbeConfig(targets, maxRedirects, verifyTLS, timeout, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

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
	discoverProbeCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverProbeCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
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

	// Route Command
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

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverRouteConfig(target, requireBaseURLMatch, ignoreStaticAssets, spiderDepth, maxRedirects, verifyTLS, timeout, threads, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

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
	discoverRouteCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
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

	// SaaS Command
	// Subcommands: active
	discoverSaasCmd := &cobra.Command{
		Use:   "saas",
		Short: "Gather SaaS information given an organization name",
		Long:  `Gather SaaS information given an organization name`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get the Orgs
			orgs, err := cmd.Flags().GetStringSlice("orgs")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get the SaaS and SSO fingerprints from the files
			saasFilePaths, err := cmd.Flags().GetStringSlice("saas-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ssoFilePaths, err := cmd.Flags().GetStringSlice("sso-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			saasFingerprints := discoversaashelpers.UnmarshalFingerprints(saasFilePaths)
			ssoFingerprints := discoversaashelpers.UnmarshalFingerprints(ssoFilePaths)
			if len(saasFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SaaS fingerprints found"))
				return
			}
			if len(ssoFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SSO fingerprints found"))
				return
			}

			// Filter SaaS and SSO fingerprints
			saasCompanies, err := cmd.Flags().GetStringSlice("saas-companies")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ssoCompanies, err := cmd.Flags().GetStringSlice("sso-companies")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filteredSaasFingerprints, err := discoversaashelpers.FilterFingerprints(saasCompanies, saasFingerprints)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filteredSsoFingerprints, err := discoversaashelpers.FilterFingerprints(ssoCompanies, ssoFingerprints)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(filteredSaasFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SaaS fingerprints found"))
				return
			}
			if len(filteredSsoFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SSO fingerprints found"))
				return
			}

			// Config
			maxRedirects, err := cmd.Flags().GetInt("max-redirects")
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

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate Request Method (Only headless and browserbase are supported)
			requestMethodEnum := requestMethodConfig.RequestMethodEnum
			if requestMethodEnum != common.RequestMethodHeadless && requestMethodEnum != common.RequestMethodBrowserbase {
				a.OutputSignal.AddError(errors.New("invalid request method, must be headless or browserbase"))
				return
			}

			// Get the config
			config := getDiscoverSaasConfig(orgs, saasCompanies, ssoCompanies, maxRedirects, verifyTLS, timeout, requestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate the report
			report, err := discoversaas.LaunchDiscoverSaas(cmd.Context(), config, *filteredSaasFingerprints, *filteredSsoFingerprints, requestMethodConfig.BrowserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverSaasCmd.Flags().StringSlice("orgs", []string{}, "The organization names to use for discovery")
	// Config Flags
	discoverSaasCmd.Flags().StringSlice("saas-file-paths", []string{"/opt/method/webscan/var/conf/discover/saas/saas_fingerprints.json"}, "Files containing SaaS application fingerprints")
	discoverSaasCmd.Flags().StringSlice("sso-file-paths", []string{"/opt/method/webscan/var/conf/discover/saas/sso_fingerprints.json"}, "Files containing SSO application fingerprints")
	discoverSaasCmd.Flags().StringSlice("saas-companies", []string{}, "The specific SaaS companies to use for discovery (Must be present in the SaaS fingerprints file)")
	discoverSaasCmd.Flags().StringSlice("sso-companies", []string{}, "The specific SSO companies to use for discovery (Must be present in the SSO fingerprints file)")
	discoverSaasCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverSaasCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverSaasCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	// Request Method Flags for all capture subcommands
	discoverSaasCmd.Flags().String("request-method", "HEADLESS", "Request method (headless, browserbase)")
	discoverSaasCmd.Flags().String("headless-path", "", "Path to a headless browser executable")
	discoverSaasCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time in seconds to wait for DOM to stabilize")
	discoverSaasCmd.Flags().String("browserbase-token", "", "Browserbase API token")
	discoverSaasCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverSaasCmd.Flags().Bool("browserbase-proxy", false, "Instruct Browserbase to use a proxy")
	discoverSaasCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for the proxy")

	_ = discoverSaasCmd.MarkFlagRequired("orgs")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverSaasCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

// getDiscoverApplicationConfig builds the config for application fingerprinting discovery.
func getDiscoverApplicationConfig(targets []string, resource string, moduleEnums []string, fingerprints *discover.ApplicationResource, successfulOnly bool, verifyTLS bool, timeout int) (*discover.DiscoverApplicationConfig, error) {
	resourceEnum, err := getDiscoverApplicationResourceConfigTypeFromString(resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resource)
	}
	config := &discover.DiscoverApplicationConfig{
		Targets:      targets,
		ResourceType: &resourceEnum,
		Modules:      moduleEnums,
		VerifyTls:    verifyTLS,
		Timeout:      max(timeout, 0),
	}
	return config, nil
}

// getDiscoverPageConfig builds the config for page capture and analysis.
func getDiscoverPageConfig(target string, maxRedirects int, verifyTLS bool, timeout int, takeScreenshot bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverPageConfig {
	config := discover.DiscoverPageConfig{
		Target:            target,
		MaxRedirects:      maxRedirects,
		VerifyTls:         verifyTLS,
		Timeout:           max(timeout, 0),
		Screenshot:        takeScreenshot,
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return config
}

// getDiscoverProbeConfig builds the config for probe discovery.
func getDiscoverProbeConfig(targets []string, maxRedirects int, verifyTLS bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) *discover.DiscoverProbeConfig {
	config := &discover.DiscoverProbeConfig{
		Targets:           targets,
		MaxRedirects:      maxRedirects,
		VerifyTls:         verifyTLS,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}

	return config
}

// getDiscoverRouteConfig builds the config for route discovery.
func getDiscoverRouteConfig(target string, requiredBaseURLMatch bool, ignoreStaticAssets bool, spiderDepth int, maxRedirects int, verifyTLS bool, timeout int, threads int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverRouteConfig {
	config := discover.DiscoverRouteConfig{
		Target:              target,
		IgnoreStaticAssets:  ignoreStaticAssets,
		RequireBaseUrlMatch: requiredBaseURLMatch,
		SpiderDepth:         spiderDepth,
		MaxRedirects:        maxRedirects,
		VerifyTls:           verifyTLS,
		Timeout:             max(timeout, 0),
		Threads:             max(threads, 0),
		RequestMethod:       requestMethod,
		HeadlessConfig:      headlessConfig,
		BrowserbaseConfig:   browserbaseConfig,
	}
	return config
}

// getDiscoverSaasConfig builds the config for SaaS active discovery.
func getDiscoverSaasConfig(orgs []string, saasCompanies []string, ssoCompanies []string, maxRedirects int, verifyTLS bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverSaasConfig {
	config := discover.DiscoverSaasConfig{
		Orgs:              orgs,
		SaasCompanies:     saasCompanies,
		SsoCompanies:      ssoCompanies,
		MaxRedirects:      maxRedirects,
		VerifyTls:         verifyTLS,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return config
}

func getDiscoverApplicationResourceConfigTypeFromString(resource string) (discover.ApplicationResourceConfigType, error) {
	if resource == "ALL" {
		return discover.ApplicationResourceConfigType{
			ApplicationResourceTypeAll: discover.ApplicationResourceTypeAllAll,
		}, nil
	}
	resourceEnum, err := discover.NewApplicationResourceTypeFromString(resource)
	if err != nil {
		return discover.ApplicationResourceConfigType{}, fmt.Errorf("invalid resource type: %s", resource)
	}
	return discover.ApplicationResourceConfigType{
		ApplicationResourceType: resourceEnum,
	}, nil
}
