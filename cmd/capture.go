package cmd

import (
	"fmt"
	"strings"

	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	routefern "github.com/Method-Security/webscan/generated/go/capture/route"
	captureroutestaticassetfern "github.com/Method-Security/webscan/generated/go/capture/route/staticasset"
	common "github.com/Method-Security/webscan/generated/go/common"
	capturepage "github.com/Method-Security/webscan/internal/capture/page"
	routecapture "github.com/Method-Security/webscan/internal/capture/route"
	captureroutestaticasset "github.com/Method-Security/webscan/internal/capture/route/staticasset"
	"github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitCaptureCommand initializes the capture command for the webscan CLI. This command is used to collect
// the HTML, screenshots, and routes of a webpage from a URL target.
func (a *WebScan) InitCaptureCommand() {
	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Perform a webpage capture against a URL target",
		Long:  `Perform a webpage capture against a URL target using various capture methods including request, browser, and browserbase.`,
	}

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
			timeout, err := cmd.Flags().GetInt("timeout")
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
			takeScreenshot, err := cmd.Flags().GetBool("screenshot")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if takeScreenshot && (requestMethodEnum == common.RequestMethodHeadless || requestMethodEnum == common.RequestMethodBrowserbase) {
				a.OutputSignal.AddError(fmt.Errorf("screenshot flag is not supported for headless or browserbase capture methods"))
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
			config := getCapturePageConfig(target, timeout, takeScreenshot, insecure, maxRedirects, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Perform Capture
			report := capturepage.PerformCapturePage(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	capturePageCmd.Flags().String("target", "", "URL target to perform webpage capture")
	capturePageCmd.Flags().Bool("screenshot", false, "Take a screenshot in addition to capturing HTML")
	capturePageCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	capturePageCmd.Flags().Bool("insecure", false, "Allow insecure connections")

	_ = capturePageCmd.MarkFlagRequired("target")

	// Route capture subcommand
	captureRouteCmd := &cobra.Command{
		Use:   "route",
		Short: "Capture routes and URLs from a webpage",
		Long:  `Capture routes and URLs from a webpage using a capture method.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			log := svc1log.FromContext(cmd.Context())

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
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			insecure, err := cmd.Flags().GetBool("insecure")
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

			config := getCaptureRouteConfig(target, baseURLsOnly, maxRedirects, timeout, insecure, requestMethodEnum, headlessConfig, browserbaseConfig)

			report := routecapture.PerformRouteCapture(cmd.Context(), config, browserbaseSecrets)
			log.Info("Route capture successful", svc1log.SafeParam("target", target))

			a.OutputSignal.Content = report
		},
	}
	captureRouteCmd.Flags().String("target", "", "URL target to perform webpage capture")
	captureRouteCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	captureRouteCmd.Flags().Bool("base-urls-only", true, "Only match routes and urls that share the base URLs domain")
	captureRouteCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	captureRouteCmd.Flags().Bool("insecure", false, "Allow insecure connections")

	_ = captureRouteCmd.MarkFlagRequired("target")

	// Static asset capture subcommand
	staticCaptureCmd := &cobra.Command{
		Use:   "static",
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
			successfulOnly, err := cmd.Flags().GetBool("successful-only")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			insecure, err := cmd.Flags().GetBool("insecure")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
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

			// Get Capture Method flag
			captureMethod, err := cmd.Flags().GetString("capture-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			captureMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(captureMethod))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Handle Headless Browser flags
			var headlessConfig *common.HeadlessConfig
			if captureMethodEnum == common.RequestMethodHeadless {
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
			if captureMethodEnum == common.RequestMethodBrowserbase {
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

			config := getCaptureRouteStaticAssetTakeOverConfig(target, baseURLsOnly, maxRedirects, timeout, insecure, successfulOnly, fingerprints, captureMethodEnum, headlessConfig, browserbaseConfig)

			// Perform Static Asset Takeover Analysis
			report := captureroutestaticasset.PerformStaticAssetTakeOverAnalysis(cmd.Context(), config, browserbaseSecrets)
			a.OutputSignal.Content = report

		},
	}
	staticCaptureCmd.Flags().String("target", "", "URL target to perform webpage capture")
	staticCaptureCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	staticCaptureCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	staticCaptureCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	staticCaptureCmd.Flags().StringSlice("fingerprint-file-paths", []string{"configs/staticassettakeover.json"}, "Fingerprint filepaths to use for fingerprinting")
	staticCaptureCmd.Flags().Bool("successful-only", false, "Only show successful attempts")
	staticCaptureCmd.Flags().Bool("base-urls-only", true, "Only match routes and urls that share the base URLs domain")

	_ = staticCaptureCmd.MarkFlagRequired("target")

	captureCmd.AddCommand(capturePageCmd, captureRouteCmd, staticCaptureCmd)
	a.RootCmd.AddCommand(captureCmd)
}

func getCapturePageConfig(target string, timeout int, takeScreenshot bool, insecure bool, maxRedirects int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserbaseConfig *common.BrowserbaseConfig) capturepagefern.CapturePageConfig {
	capturePageConfig := capturepagefern.CapturePageConfig{
		Target:            target,
		RequestMethod:     requestMethod,
		TakeScreenshot:    takeScreenshot,
		Insecure:          insecure,
		MaxRedirects:      maxRedirects,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	if timeout > 0 {
		capturePageConfig.Timeout = timeout
	} else {
		capturePageConfig.Timeout = 0
	}
	return capturePageConfig
}

func getCaptureRouteConfig(target string, baseURLSOnly bool, maxRedirects int, timeout int, insecure bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserbaseConfig *common.BrowserbaseConfig) routefern.CaptureRouteConfig {
	routeCaptureConfig := routefern.CaptureRouteConfig{
		Target:            target,
		StaticAssets:      false,
		MaxRedirects:      maxRedirects,
		BaseUrLsOnly:      baseURLSOnly,
		Timeout:           timeout,
		Insecure:          insecure,
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return routeCaptureConfig
}

func getCaptureRouteStaticAssetTakeOverConfig(target string, baseURLSOnly bool, maxRedirects int, timeout int, insecure bool, successfulOnly bool, fingerprints []*captureroutestaticassetfern.StaticAssetTakeOverFingerprint, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserBaseConfig *common.BrowserbaseConfig) captureroutestaticassetfern.StaticAssetTakeOverConfig {
	captureRouteConfig := &routefern.CaptureRouteConfig{
		Target:            target,
		BaseUrLsOnly:      baseURLSOnly,
		Timeout:           timeout,
		Insecure:          insecure,
		RequestMethod:     requestMethod,
		MaxRedirects:      maxRedirects,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserBaseConfig,
	}

	return captureroutestaticassetfern.StaticAssetTakeOverConfig{
		CaptureRouteConfig: captureRouteConfig,
		SuccessfulOnly:     successfulOnly,
		Fingerprints:       fingerprints,
	}
}
