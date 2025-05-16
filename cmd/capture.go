package cmd

import (
	// Standard
	"fmt"
	"strings"

	// Generated
	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	route "github.com/Method-Security/webscan/generated/go/capture/route"
	captureroutestaticassetfern "github.com/Method-Security/webscan/generated/go/capture/route/staticasset"
	common "github.com/Method-Security/webscan/generated/go/common"

	// Internal
	capturepage "github.com/Method-Security/webscan/internal/capture/page"
	captureroute "github.com/Method-Security/webscan/internal/capture/route"
	captureroutestaticasset "github.com/Method-Security/webscan/internal/capture/route/staticasset"

	// Utils
	browserbase "github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
	// External
	cobra "github.com/spf13/cobra"
)

func (a *WebScan) InitCaptureCommand() {
	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Perform a webpage capture against a URL target",
		Long:  `Perform a webpage capture against a URL target using various capture methods including request, browser, and browserbase.`,
	}
	// Request Method Flags for all capture subcommands
	captureCmd.PersistentFlags().String("request-method", "STANDARD", "Request method (standard, headless, browserbase)")
	captureCmd.PersistentFlags().String("headless-path", "", "Path to a headless browser executable")
	captureCmd.PersistentFlags().Int("min-dom-stabalize-time", 10, "Minimum time in seconds to wait for DOM to stabilize")
	captureCmd.PersistentFlags().String("browserbase-token", "", "Browserbase API token")
	captureCmd.PersistentFlags().String("browserbase-project", "", "Browserbase project ID")
	captureCmd.PersistentFlags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	captureCmd.PersistentFlags().StringSlice("countries", []string{}, "List of countries to use for the proxy")

	// Page capture subcommand
	capturePageCmd := &cobra.Command{
		Use:   "page",
		Short: "Capture HTML and optionally take a screenshot of a webpage",
		Long:  `Capture HTML and optionally take a screenshot of a webpage using a capture method.`,
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

			// Get request method
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
				browserbaseSecrets = &common.BrowserbaseSecrets{
					Project: projectStr,
					Token:   tokenStr,
				}
			}

			// Set Config
			config := getCapturePageConfig(target, maxRedirects, insecure, timeout, takeScreenshot, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate a report
			report := capturepage.PerformCapturePage(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	capturePageCmd.Flags().String("target", "", "URL target to perform webpage capture")
	capturePageCmd.Flags().Bool("screenshot", false, "Take a screenshot in addition to capturing HTML")
	capturePageCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	capturePageCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	capturePageCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")

	_ = capturePageCmd.MarkFlagRequired("target")

	captureCmd.AddCommand(capturePageCmd)

	// Route capture subcommand
	captureRouteCmd := &cobra.Command{
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
			baseURLsOnly, err := cmd.Flags().GetBool("base-urls-only")
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

			// Handle browserbase-specific flags
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
				browserbaseSecrets = &common.BrowserbaseSecrets{
					Token:   tokenStr,
					Project: projectStr,
				}
			}

			// Set Config
			config := getCaptureRouteConfig(target, baseURLsOnly, maxRedirects, insecure, timeout, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate a report
			report := captureroute.PerformCaptureRoute(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	captureRouteCmd.Flags().String("target", "", "URL target to perform webpage capture")
	captureRouteCmd.Flags().Bool("base-urls-only", true, "Only match routes and urls that share the base URLs domain")
	captureRouteCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	captureRouteCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	captureRouteCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")

	_ = captureRouteCmd.MarkFlagRequired("target")

	// Static asset capture subcommand
	staticCaptureCmd := &cobra.Command{
		Use:   "static-asset-takeover",
		Short: "Capture static assets from a webpage and perform static asset takeover analysis",
		Long:  `Capture static assets from a webpage and perform static asset takeover analysis using a fingerprinting method.`,
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
			fingerprints := captureroutestaticasset.GrabStaticAssetTakeOverFingerprints(fingerprintPaths)
			baseURLsOnly, err := cmd.Flags().GetBool("base-urls-only")
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

			// Get Capture Method flag
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
			var headlessConfig *common.HeadlessConfig
			if requestMethodEnum == common.RequestMethodHeadless {
				bPath, err := cmd.Flags().GetString("headless-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				headlessConfig = &common.HeadlessConfig{
					PathToBrowser: &bPath,
				}
			}

			// Handle Browserbase flags
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
				browserbaseSecrets = &common.BrowserbaseSecrets{
					Token:   tokenStr,
					Project: projectStr,
				}
			}

			// Set Config
			config := getCaptureRouteStaticAssetTakeOverConfig(target, fingerprints, baseURLsOnly, successfulOnly, maxRedirects, insecure, timeout, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate a report
			report := captureroutestaticasset.PerformStaticAssetTakeOverAnalysis(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report

		},
	}
	staticCaptureCmd.Flags().String("target", "", "URL target to perform webpage capture")
	staticCaptureCmd.Flags().Bool("base-urls-only", false, "Only match routes and urls that share the base URLs domain")
	staticCaptureCmd.Flags().Bool("successful-only", false, "Only show successful attempts")
	staticCaptureCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	staticCaptureCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	staticCaptureCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	staticCaptureCmd.Flags().StringSlice("fingerprint-file-paths", []string{"configs/capture/route/static_asset_takeover.json"}, "Fingerprint filepaths to use for fingerprinting")

	_ = staticCaptureCmd.MarkFlagRequired("target")

	captureRouteCmd.AddCommand(staticCaptureCmd)

	captureCmd.AddCommand(captureRouteCmd)

	captureCmd.AddCommand(capturePageCmd)
	a.RootCmd.AddCommand(captureCmd)
}

func getCapturePageConfig(target string, maxRedirects int, insecure bool, timeout int, takeScreenshot bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserbaseConfig *common.BrowserbaseConfig) capturepagefern.CapturePageConfig {
	capturePageConfig := capturepagefern.CapturePageConfig{
		Target:            target,
		MaxRedirects:      maxRedirects,
		Insecure:          insecure,
		Timeout:           max(timeout, 0),
		TakeScreenshot:    takeScreenshot,
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return capturePageConfig
}

func getCaptureRouteConfig(target string, baseURLSOnly bool, maxRedirects int, insecure bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserbaseConfig *common.BrowserbaseConfig) route.CaptureRouteConfig {
	capturerouteConfig := route.CaptureRouteConfig{
		Target:            target,
		StaticAssets:      false,
		MaxRedirects:      maxRedirects,
		BaseUrLsOnly:      baseURLSOnly,
		Insecure:          insecure,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return capturerouteConfig
}

func getCaptureRouteStaticAssetTakeOverConfig(target string, fingerprints []*captureroutestaticassetfern.StaticAssetTakeOverFingerprint, baseURLSOnly bool, successfulOnly bool, maxRedirects int, insecure bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserBaseConfig *common.BrowserbaseConfig) captureroutestaticassetfern.StaticAssetTakeOverConfig {
	captureRouteConfig := &route.CaptureRouteConfig{
		Target:            target,
		StaticAssets:      true,
		BaseUrLsOnly:      baseURLSOnly,
		Insecure:          insecure,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		MaxRedirects:      maxRedirects,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserBaseConfig,
	}

	return captureroutestaticassetfern.StaticAssetTakeOverConfig{
		CaptureRouteConfig: captureRouteConfig,
		Fingerprints:       fingerprints,
		SuccessfulOnly:     successfulOnly,
	}
}
