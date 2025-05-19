package cmd

import (
	// Standard
	"fmt"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discoverfern "github.com/Method-Security/webscan/generated/go/discover"
	discoverroutefern "github.com/Method-Security/webscan/generated/go/discover/route"

	// Internal
	discover "github.com/Method-Security/webscan/internal/discover"
	discoverapplication "github.com/Method-Security/webscan/internal/discover/application"
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route"
	discoverroutestaticasset "github.com/Method-Security/webscan/internal/discover/route/staticasset"

	// Utils
	browserbase "github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
	// External
	cobra "github.com/spf13/cobra"
)

func (a *WebScan) InitDiscoverCommand() {
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Perform various discovery scans",
		Long:  `Perform various discovery scans`,
	}

	discoverApplicationCmd := &cobra.Command{
		Use:   "application",
		Short: "Perform a application fingerprint scan against a target",
		Long:  `Perform a application fingerprint scan against a target using specified types.`,
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
			config, err := newApplicationFingerprintConfig(targets, resourceType, modules, filteredFingerprints, successfulOnly, insecure, timeout)
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
	discoverApplicationCmd.Flags().StringSlice("targets", []string{}, "URL target to perform fingerprint against")
	// Config Flags
	discoverApplicationCmd.Flags().String("fingerprint-file", "configs/discover/application/fingerprints.json", "Path to the fingerprint file to use for fingerprinting")
	discoverApplicationCmd.Flags().String("resource-type", "", "Defined resource type to fingerprint")
	discoverApplicationCmd.Flags().StringSlice("modules", []string{}, "Defined resource type modules to run")
	discoverApplicationCmd.Flags().Bool("successful-only", false, "Only show successful attempts")
	discoverApplicationCmd.Flags().Bool("insecure", false, "Allow insecure SSL connections and transfers")
	discoverApplicationCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	// Mark Required Flags
	_ = discoverApplicationCmd.MarkFlagRequired("targets")
	_ = discoverApplicationCmd.MarkFlagRequired("resource-type")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverApplicationCmd)

	discoverPageCmd := &cobra.Command{
		Use:   "page",
		Short: "Perform a page discovery scan against a target",
		Long:  `Perform a page discovery scan against a target using a given request method.`,
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
			requestMethod, err := cmd.Flags().GetString("request-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
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
			if takeScreenshot && (requestMethodEnum == common.RequestMethodStandard || requestMethodEnum == common.RequestMethodBrowserbase) {
				a.OutputSignal.AddError(fmt.Errorf("screenshot flag is not supported for standard or browserbase capture methods"))
				return
			}

			// Flags for headless browser or Browserbase
			var headlessConfig *common.HeadlessRequestConfig
			if requestMethodEnum == common.RequestMethodHeadless || requestMethodEnum == common.RequestMethodBrowserbase {
				bPath, err := cmd.Flags().GetString("headless-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig = &common.HeadlessRequestConfig{
					PathToBrowserShell: &bPath,
				}
				domTime, err := cmd.Flags().GetInt("min-dom-stabalize-time")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig.MinDomStabalizeTime = domTime
			}

			// Flags for browserbase
			var browserbaseConfig *common.BrowserbaseRequestConfig
			var browserbaseSecrets *common.BrowserbaseRequestSecrets
			if requestMethodEnum == common.RequestMethodBrowserbase {
				// Config flags
				proxy, err := cmd.Flags().GetBool("browserbase-proxy")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				countries, err := cmd.Flags().GetStringSlice("browserbase-countries")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseConfig = &common.BrowserbaseRequestConfig{
					Proxy:     &proxy,
					Countries: countries,
				}

				// Environment variables
				tokenStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-token", "BROWSERBASE_TOKEN")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				projectStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-project", "BROWSERBASE_PROJECT")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseSecrets = &common.BrowserbaseRequestSecrets{
					Project: projectStr,
					Token:   tokenStr,
				}
			}

			// Set Config
			config := getPageCaptureConfig(target, maxRedirects, insecure, timeout, takeScreenshot, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate a report
			report := discoverpage.PerformPageCapture(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverPageCmd.Flags().String("target", "", "URL target to perform webpage capture")
	// Config Flags
	discoverPageCmd.Flags().Bool("screenshot", false, "Take a screenshot in addition to capturing HTML")
	discoverPageCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverPageCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	discoverPageCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	// Request Method Flags for all capture subcommands
	discoverPageCmd.Flags().String("request-method", "STANDARD", "Request method (standard, headless, browserbase)")
	discoverPageCmd.Flags().String("headless-path", "", "Path to a headless browser executable")
	discoverPageCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time in seconds to wait for DOM to stabilize")
	discoverPageCmd.Flags().String("browserbase-token", "", "Browserbase API token")
	discoverPageCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverPageCmd.Flags().Bool("browserbase-proxy", false, "Instruct Browserbase to use a proxy")
	discoverPageCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for the browserbase proxy")

	// Mark Required Flags
	_ = discoverPageCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverPageCmd)

	discoverProbeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Perform a web probe against targets to identify existence of web applications",
		Long:  `Perform a web probe against targets to identify existence of web applications`,
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
			onlyHTTPS, err := cmd.Flags().GetBool("only-https")
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
			requestMethod, err := cmd.Flags().GetString("request-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Flags for headless browser or browserbase
			var headlessConfig *common.HeadlessRequestConfig
			if requestMethodEnum == common.RequestMethodHeadless || requestMethodEnum == common.RequestMethodBrowserbase {
				bPath, err := cmd.Flags().GetString("headless-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig = &common.HeadlessRequestConfig{
					PathToBrowserShell: &bPath,
				}
				domTime, err := cmd.Flags().GetInt("min-dom-stabalize-time")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig.MinDomStabalizeTime = domTime
			}

			// Flags for browserbase
			var browserbaseConfig *common.BrowserbaseRequestConfig
			var browserbaseSecrets *common.BrowserbaseRequestSecrets
			if requestMethodEnum == common.RequestMethodBrowserbase {
				// Config flags
				proxy, err := cmd.Flags().GetBool("browserbase-proxy")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				countries, err := cmd.Flags().GetStringSlice("browserbase-countries")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseConfig = &common.BrowserbaseRequestConfig{
					Proxy:     &proxy,
					Countries: countries,
				}

				// Environment variables
				tokenStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-token", "BROWSERBASE_TOKEN")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				projectStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-project", "BROWSERBASE_PROJECT")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseSecrets = &common.BrowserbaseRequestSecrets{
					Project: projectStr,
					Token:   tokenStr,
				}
			}

			// Set Config
			config := getWebProbeConfig(targets, maxRedirects, onlyHTTPS, insecure, timeout, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate report
			report, err := discover.PerformWebProbe(cmd.Context(), config, browserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverProbeCmd.Flags().StringSlice("targets", []string{}, "Address targets to perform web application probing against, comma delimited list")
	// Config Flags
	discoverProbeCmd.Flags().Bool("only-https", true, "Only perform probing over HTTPS")
	discoverProbeCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverProbeCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	discoverProbeCmd.Flags().Int("timeout", 30, "Timeout limit (Seconds)")
	// Request Method Flags
	discoverProbeCmd.Flags().String("request-method", "STANDARD", "Request method (standard, headless, browserbase)")
	discoverProbeCmd.Flags().String("headless-path", "", "Path to a headless browser executable")
	discoverProbeCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time in seconds to wait for DOM to stabilize")
	discoverProbeCmd.Flags().String("browserbase-token", "", "Browserbase API token")
	discoverProbeCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverProbeCmd.Flags().Bool("browserbase-proxy", false, "Instruct Browserbase to use a proxy")
	discoverProbeCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for the Browserbase proxy")

	// Mark Required Flags
	_ = discoverProbeCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverProbeCmd)

	discoverRouteCmd := &cobra.Command{
		Use:   "route",
		Short: "Capture routes and URLs from a webpage",
		Long:  `Capture routes and URLs from a webpage using a given request method.`,
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
			requestMethod, err := cmd.Flags().GetString("request-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Handle headless or browserbase-specific flags
			var headlessConfig *common.HeadlessRequestConfig
			if requestMethodEnum == common.RequestMethodHeadless || requestMethodEnum == common.RequestMethodBrowserbase {
				bPath, err := cmd.Flags().GetString("headless-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig = &common.HeadlessRequestConfig{
					PathToBrowserShell: &bPath,
				}
				domTime, err := cmd.Flags().GetInt("min-dom-stabalize-time")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig.MinDomStabalizeTime = domTime
			}

			// Handle browserbase-specific flags
			var browserbaseConfig *common.BrowserbaseRequestConfig
			var browserbaseSecrets *common.BrowserbaseRequestSecrets
			if requestMethodEnum == common.RequestMethodBrowserbase {
				// Config flags
				proxy, err := cmd.Flags().GetBool("browserbase-proxy")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				countries, err := cmd.Flags().GetStringSlice("browserbase-countries")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseConfig = &common.BrowserbaseRequestConfig{
					Proxy:     &proxy,
					Countries: countries,
				}

				// Environment variables
				tokenStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-token", "BROWSERBASE_TOKEN")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				projectStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-project", "BROWSERBASE_PROJECT")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseSecrets = &common.BrowserbaseRequestSecrets{
					Token:   tokenStr,
					Project: projectStr,
				}
			}

			// Set Config
			config := getRouteCaptureConfig(target, requireBaseURLMatch, ignoreStaticAssets, spiderDepth, maxRedirects, insecure, timeout, threads, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate a report
			report := discoverroute.PerformRouteCapture(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverRouteCmd.Flags().String("target", "", "URL target to perform webpage capture")
	// Config Flags
	discoverRouteCmd.Flags().Bool("require-base-url-match", true, "Only scan routes that share the base url as the target")
	discoverRouteCmd.Flags().Bool("ignore-static-assets", true, "Ignore static assets when spidering routes")
	discoverRouteCmd.Flags().Int("spider-depth", 1, "Maximum number of hops to follow when spidering routes")
	discoverRouteCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverRouteCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	discoverRouteCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	discoverRouteCmd.Flags().Int("threads", 0, "Number of threads to use for the capture")

	// Request Method Flags
	discoverRouteCmd.Flags().String("request-method", "STANDARD", "Request method (standard, headless, browserbase)")
	discoverRouteCmd.Flags().String("headless-path", "", "Path to a headless browser executable")
	discoverRouteCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time in seconds to wait for DOM to stabilize")
	discoverRouteCmd.Flags().String("browserbase-token", "", "Browserbase API token")
	discoverRouteCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverRouteCmd.Flags().Bool("browserbase-proxy", false, "Instruct Browserbase to use a proxy")
	discoverRouteCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for the proxy")

	// Mark Required Flags
	_ = discoverRouteCmd.MarkFlagRequired("target")

	discoverRouteStaticAssetTakeoverCmd := &cobra.Command{
		Use:   "static-asset-takeover",
		Short: "Capture static assets from a webpage and assess them for static asset takeover",
		Long:  `Capture static assets from a webpage and assess them for static asset takeover using a fingerprinting method.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config flags
			fingerprintPaths, err := cmd.Flags().GetStringSlice("fingerprint-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fingerprints := discoverroutestaticasset.GrabStaticAssetTakeOverFingerprints(fingerprintPaths)
			if len(fingerprints) == 0 {
				a.OutputSignal.AddError(fmt.Errorf("no fingerprints found"))
				return
			}
			requireBaseURLMatch, err := cmd.Flags().GetBool("require-base-url-match")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successful-only")
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
			requestMethod, err := cmd.Flags().GetString("request-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Handle Headless Browser flags
			var headlessConfig *common.HeadlessRequestConfig
			if requestMethodEnum == common.RequestMethodHeadless {
				bPath, err := cmd.Flags().GetString("headless-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig = &common.HeadlessRequestConfig{
					PathToBrowserShell: &bPath,
				}
				domTime, err := cmd.Flags().GetInt("min-dom-stabalize-time")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig.MinDomStabalizeTime = domTime
			}

			// Handle Browserbase flags
			var browserbaseConfig *common.BrowserbaseRequestConfig
			var browserbaseSecrets *common.BrowserbaseRequestSecrets
			if requestMethodEnum == common.RequestMethodBrowserbase {
				// Config flags
				proxy, err := cmd.Flags().GetBool("browserbase-proxy")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				countries, err := cmd.Flags().GetStringSlice("browserbase-countries")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseConfig = &common.BrowserbaseRequestConfig{
					Proxy:     &proxy,
					Countries: countries,
				}

				// Environment variables
				tokenStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-token", "BROWSERBASE_TOKEN")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				projectStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "browserbase-project", "BROWSERBASE_PROJECT")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserbaseSecrets = &common.BrowserbaseRequestSecrets{
					Token:   tokenStr,
					Project: projectStr,
				}
			}

			// Set Config
			config := getStaticAssetTakeoverConfig(target, fingerprints, requireBaseURLMatch, successfulOnly, maxRedirects, insecure, timeout, threads, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate a report
			report := discoverroutestaticasset.DetectStaticAssetTakeovers(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report

		},
	}
	// Target Flags
	discoverRouteStaticAssetTakeoverCmd.Flags().String("target", "", "URL target to perform webpage capture")
	// Config Flags
	discoverRouteStaticAssetTakeoverCmd.Flags().StringSlice("fingerprint-file-paths", []string{"configs/discover/route/static_asset_takeover.json"}, "Fingerprint filepaths to use for fingerprinting")
	discoverRouteStaticAssetTakeoverCmd.Flags().Bool("require-base-url-match", false, "Only scan routes and static assets that share the base url as the target")
	discoverRouteStaticAssetTakeoverCmd.Flags().Bool("successful-only", false, "Only show successful attempts")
	discoverRouteStaticAssetTakeoverCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverRouteStaticAssetTakeoverCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	discoverRouteStaticAssetTakeoverCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	discoverRouteStaticAssetTakeoverCmd.Flags().Int("threads", 0, "Number of threads to use for the capture")
	// Request Method Flags for all capture subcommands
	discoverRouteStaticAssetTakeoverCmd.Flags().String("request-method", "STANDARD", "Request method (standard, headless, browserbase)")
	discoverRouteStaticAssetTakeoverCmd.Flags().String("headless-path", "", "Path to a headless browser executable")
	discoverRouteStaticAssetTakeoverCmd.Flags().Int("min-dom-stabalize-time", 5, "Minimum time in seconds to wait for DOM to stabilize")
	discoverRouteStaticAssetTakeoverCmd.Flags().String("browserbase-token", "", "Browserbase API token")
	discoverRouteStaticAssetTakeoverCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverRouteStaticAssetTakeoverCmd.Flags().Bool("browserbase-proxy", false, "Instruct Browserbase to use a proxy")
	discoverRouteStaticAssetTakeoverCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for the proxy")

	// Mark Required Flags
	_ = discoverRouteStaticAssetTakeoverCmd.MarkFlagRequired("target")

	// Add Command to 'Discover Route' Command
	discoverRouteCmd.AddCommand(discoverRouteStaticAssetTakeoverCmd)

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverRouteCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

func newApplicationFingerprintConfig(targets []string, resource string, moduleEnums []string, fingerprints *discoverfern.ApplicationFingerprintResource, successfulOnly bool, insecure bool, timeout int) (*discoverfern.ApplicationFingerprintConfig, error) {
	resourceEnum, err := discoverfern.NewApplicationFingerprintResourceTypeFromString(resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resource)
	}
	config := &discoverfern.ApplicationFingerprintConfig{
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

func getPageCaptureConfig(target string, maxRedirects int, insecure bool, timeout int, takeScreenshot bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discoverfern.PageCaptureConfig {
	config := discoverfern.PageCaptureConfig{
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

func getWebProbeConfig(targets []string, maxRedirects int, onlyHTTPS bool, insecure bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) *discoverfern.WebProbeConfig {
	config := &discoverfern.WebProbeConfig{
		Targets:           targets,
		MaxRedirects:      maxRedirects,
		OnlyHttps:         onlyHTTPS,
		Insecure:          insecure,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}

	return config
}

func getRouteCaptureConfig(target string, requiredBaseURLMatch bool, ignoreStaticAssets bool, spiderDepth int, maxRedirects int, insecure bool, timeout int, threads int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discoverroutefern.RouteCaptureConfig {
	config := discoverroutefern.RouteCaptureConfig{
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

func getStaticAssetTakeoverConfig(target string, fingerprints []*discoverroutefern.StaticAssetTakeoverFingerprint, requireBaseURLMatch bool, successfulOnly bool, maxRedirects int, insecure bool, timeout int, threads int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserBaseConfig *common.BrowserbaseRequestConfig) discoverroutefern.StaticAssetTakeoverConfig {
	// Create Route Capture Config
	routeCaptureConfig := &discoverroutefern.RouteCaptureConfig{
		Target:              target,
		IgnoreStaticAssets:  false,
		RequireBaseUrlMatch: requireBaseURLMatch,
		SpiderDepth:         1,
		Insecure:            insecure,
		Timeout:             max(timeout, 0),
		Threads:             max(threads, 0),
		RequestMethod:       requestMethod,
		MaxRedirects:        maxRedirects,
		HeadlessConfig:      headlessConfig,
		BrowserbaseConfig:   browserBaseConfig,
	}
	// Create Static Asset Takeover Config
	config := discoverroutefern.StaticAssetTakeoverConfig{
		RouteCaptureConfig: routeCaptureConfig,
		Fingerprints:       fingerprints,
		SuccessfulOnly:     successfulOnly,
	}

	return config
}
