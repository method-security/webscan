package cmd

import (
	"errors"

	common "github.com/Method-Security/webscan/generated/go/common"
	routecapturefern "github.com/Method-Security/webscan/generated/go/routecapture"
	"github.com/Method-Security/webscan/internal/pagecapture/helpers/browserbase"
	routecapture "github.com/Method-Security/webscan/internal/routecapture"
	staticassest "github.com/Method-Security/webscan/internal/routecapture/staticassest"
	"github.com/spf13/cobra"
)

// InitRoutecaptureCommand initializes the Routecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitRoutecaptureCommand() {
	routeCaptureCmd := &cobra.Command{
		Use:   "routecapture",
		Short: "Perform a webpage routes and URL links capture against a URL target",
		Long:  `Perform a webpage routes and URL links capture against a URL target`,
	}
	routeCaptureCmd.PersistentFlags().String("target", "", "URL target to perform webpage capture")
	routeCaptureCmd.PersistentFlags().String("browserPath", "", "Path to a browser executable")
	routeCaptureCmd.PersistentFlags().Bool("base-urls-only", true, "Only match routes and urls that share the base URLs domain")
	routeCaptureCmd.PersistentFlags().Bool("capture-static-assets", false, "Capture the routes and urls of static assets such as images, css, and js files")
	routeCaptureCmd.PersistentFlags().Int("timeout", 30, "Timeout in seconds for the capture")
	routeCaptureCmd.PersistentFlags().Int("minDOMStabalizeTime", 5, "Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots")
	routeCaptureCmd.PersistentFlags().Bool("insecure", false, "Allow insecure connections")

	requestCaptureCmd := &cobra.Command{
		Use:   "request",
		Short: "Perform a webpage route capture using a basic HTTP/HTTPS request",
		Long:  `Perform a webpage route capture using a basic HTTP/HTTPS request`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get the target
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}
			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")
			captureStaticAssets, _ := cmd.Flags().GetBool("capture-static-assets")
			insecure, _ := cmd.Flags().GetBool("insecure")
			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")

			// Return the report
			report := routecapture.PerformRouteCapture(cmd.Context(), target, common.CaptureMethodRequest, baseURLsOnly, captureStaticAssets, timeout, minDOMStabalizeTime, insecure, browserPath, nil, nil, nil)
			a.OutputSignal.Content = report
		},
	}

	routeCaptureCmd.AddCommand(requestCaptureCmd)

	browserCaptureCmd := &cobra.Command{
		Use:   "browser",
		Short: "Perform a webpage route capture using a headless browser",
		Long:  `Perform a webpage route capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get the target
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}
			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")
			captureStaticAssets, _ := cmd.Flags().GetBool("capture-static-assets")
			insecure, _ := cmd.Flags().GetBool("insecure")
			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")

			// Return the report
			report := routecapture.PerformRouteCapture(cmd.Context(), target, common.CaptureMethodBrowser, baseURLsOnly, captureStaticAssets, timeout, minDOMStabalizeTime, insecure, browserPath, nil, nil, nil)
			a.OutputSignal.Content = report
		},
	}
	browserCaptureCmd.PersistentFlags().String("browserPath", "", "Path to a browser executable")
	routeCaptureCmd.AddCommand(browserCaptureCmd)

	browserbaseCaptureCmd := &cobra.Command{
		Use:   "browserbase",
		Short: "Perform a fully rendered webpage route capture using Browserbase",
		Long:  `Perform a fully rendered webpage route capture using Browserbase. Useful for avoiding bot detection or maintaining stealth`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			countries, _ := cmd.Flags().GetStringArray("country")
			if len(countries) > 0 {
				_ = cmd.MarkFlagRequired("proxy")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get the target
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			token, err := getFlagOrEnvironmentVariable(cmd, "token", "BROWSERBASE_TOKEN")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			project, err := getFlagOrEnvironmentVariable(cmd, "project", "BROWSERBASE_PROJECT")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")
			captureStaticAssets, _ := cmd.Flags().GetBool("capture-static-assets")
			insecure, _ := cmd.Flags().GetBool("insecure")
			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")
			proxy, _ := cmd.Flags().GetBool("proxy")
			countries, _ := cmd.Flags().GetStringArray("country")

			// Create the options
			var options []browserbase.Option
			if proxy && len(countries) > 0 {
				options = append(options, browserbase.WithProxyCountries(countries))
			} else if proxy {
				options = append(options, browserbase.WithProxy())
			}

			// Return the report
			report := routecapture.PerformRouteCapture(cmd.Context(), target, common.CaptureMethodBrowserbase, baseURLsOnly, captureStaticAssets, timeout, minDOMStabalizeTime, insecure, nil, &token, &project, &options)
			a.OutputSignal.Content = report
		},
	}
	browserbaseCaptureCmd.Flags().String("token", "", "Browserbase API token")
	browserbaseCaptureCmd.Flags().String("project", "", "Browserbase project ID")
	browserbaseCaptureCmd.Flags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	browserbaseCaptureCmd.Flags().StringArray("country", []string{}, "List of countries to use for the proxy")
	routeCaptureCmd.AddCommand(browserbaseCaptureCmd)

	staticAssetCaptureCmd := &cobra.Command{
		Use:   "staticasset",
		Short: "Commands to emurate and analyze static assets of a target",
		Long:  `Commands to emurate and analyze static assets of a target`,
	}

	staticAssetTakeOverCmd := &cobra.Command{
		Use:   "takeover",
		Short: "Perform a takeover analysis on static assets of a target",
		Long:  `Perform a takeover analysis on static assets of a target`,
	}

	staticAssetTakeOverCmd.PersistentFlags().Bool("successfulonly", false, "Only return successful static asset takeovers")
	staticAssetTakeOverCmd.PersistentFlags().StringArray("fingerprintfilepaths", []string{"configs/staticassettakeover.json"}, "File path to a JSON file containing a list of fingerprints to use for the static asset takeover analysis")

	requestStaticAssetTakeOverCmd := &cobra.Command{
		Use:   "request",
		Short: "Perform a takeover analysis on static assets of a target using a basic HTTP/HTTPS request",
		Long:  `Perform a takeover analysis on static assets of a target using a basic HTTP/HTTPS request`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get the target
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}

			fingerprintFilePaths, _ := cmd.Flags().GetStringArray("fingerprintfilepaths")
			var fingerprints []routecapturefern.StaticAssetTakeOverFingerprint
			if len(fingerprintFilePaths) != 0 {
				fingerprints = staticassest.GrabStaticAssetTakeOverFingerprints(fingerprintFilePaths)

			}
			if len(fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no fingerprints found"))
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")
			insecure, _ := cmd.Flags().GetBool("insecure")
			successfulOnly, _ := cmd.Flags().GetBool("successfulonly")

			// Extract the routes and links
			report := staticassest.PerformStaticAssetTakeOverAnalysis(cmd.Context(), target, common.CaptureMethodRequest, false, timeout, minDOMStabalizeTime, insecure, browserPath, nil, nil, nil, successfulOnly, fingerprints)
			a.OutputSignal.Content = report
		},
	}

	staticAssetTakeOverCmd.AddCommand(requestStaticAssetTakeOverCmd)

	browserStaticAssetTakeOverCmd := &cobra.Command{
		Use:   "browser",
		Short: "Perform a takeover analysis on static assets of a target using a headless browser",
		Long:  `Perform a takeover analysis on static assets of a target using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}

			fingerprintFilePaths, _ := cmd.Flags().GetStringArray("fingerprintfilepaths")
			var fingerprints []routecapturefern.StaticAssetTakeOverFingerprint
			if len(fingerprintFilePaths) != 0 {
				fingerprints = staticassest.GrabStaticAssetTakeOverFingerprints(fingerprintFilePaths)

			}
			if len(fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no fingerprints found"))
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")
			insecure, _ := cmd.Flags().GetBool("insecure")
			successfulOnly, _ := cmd.Flags().GetBool("successfulonly")

			// Return the report
			report := staticassest.PerformStaticAssetTakeOverAnalysis(cmd.Context(), target, common.CaptureMethodBrowser, false, timeout, minDOMStabalizeTime, insecure, browserPath, nil, nil, nil, successfulOnly, fingerprints)
			a.OutputSignal.Content = report
		},
	}
	browserStaticAssetTakeOverCmd.Flags().String("browserPath", "", "Path to a browser executable")
	staticAssetTakeOverCmd.AddCommand(browserStaticAssetTakeOverCmd)

	browserbaseStaticAssetTakeOverCmd := &cobra.Command{
		Use:   "browserbase",
		Short: "Perform a fully rendered takeover analysis on static assets of a target using Browserbase",
		Long:  `Perform a fully rendered takeover analysis on static assets of a target using Browserbase. Useful for avoiding bot detection or maintaining stealth`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			countries, _ := cmd.Flags().GetStringArray("country")
			if len(countries) > 0 {
				_ = cmd.MarkFlagRequired("proxy")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get the target
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			token, err := getFlagOrEnvironmentVariable(cmd, "token", "BROWSERBASE_TOKEN")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			project, err := getFlagOrEnvironmentVariable(cmd, "project", "BROWSERBASE_PROJECT")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			fingerprintFilePaths, _ := cmd.Flags().GetStringArray("fingerprintfilepaths")
			var fingerprints []routecapturefern.StaticAssetTakeOverFingerprint
			if len(fingerprintFilePaths) != 0 {
				fingerprints = staticassest.GrabStaticAssetTakeOverFingerprints(fingerprintFilePaths)

			}
			if len(fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no fingerprints found"))
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")
			insecure, _ := cmd.Flags().GetBool("insecure")
			proxy, _ := cmd.Flags().GetBool("proxy")
			countries, _ := cmd.Flags().GetStringArray("country")
			successfulOnly, _ := cmd.Flags().GetBool("successfulonly")

			// Create the options
			var options []browserbase.Option
			if proxy && len(countries) > 0 {
				options = append(options, browserbase.WithProxyCountries(countries))
			} else if proxy {
				options = append(options, browserbase.WithProxy())
			}

			// Return the report
			report := staticassest.PerformStaticAssetTakeOverAnalysis(cmd.Context(), target, common.CaptureMethodBrowserbase, false, timeout, minDOMStabalizeTime, insecure, nil, &token, &project, &options, successfulOnly, fingerprints)
			a.OutputSignal.Content = report
		},
	}
	browserbaseStaticAssetTakeOverCmd.Flags().String("token", "", "Browserbase API token")
	browserbaseStaticAssetTakeOverCmd.Flags().String("project", "", "Browserbase project ID")
	browserbaseStaticAssetTakeOverCmd.Flags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	browserbaseStaticAssetTakeOverCmd.Flags().StringArray("country", []string{}, "List of countries to use for the proxy")
	staticAssetTakeOverCmd.AddCommand(browserbaseStaticAssetTakeOverCmd)

	staticAssetCaptureCmd.AddCommand(staticAssetTakeOverCmd)
	routeCaptureCmd.AddCommand(staticAssetCaptureCmd)

	a.RootCmd.AddCommand(routeCaptureCmd)
}
