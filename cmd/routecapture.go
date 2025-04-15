package cmd

import (
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/internal/pagecapture/helpers/browserbase"
	routecapture "github.com/Method-Security/webscan/internal/routecapture"
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

	requestCaptureCmd := &cobra.Command{
		Use:   "request",
		Short: "Perform a webpage route capture using a basic HTTP/HTTPS request",
		Long:  `Perform a webpage route capture using a basic HTTP/HTTPS request`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			insecure, _ := cmd.Flags().GetBool("insecure")

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

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

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")

			// Extract the routes and links
			report := routecapture.PerformRouteCapture(cmd.Context(), target, common.CaptureMethodRequest, baseURLsOnly, captureStaticAssets, timeout, minDOMStabalizeTime, insecure, browserPath, nil, nil, nil)
			a.OutputSignal.Content = report
		},
	}
	requestCaptureCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	routeCaptureCmd.AddCommand(requestCaptureCmd)

	browserCaptureCmd := &cobra.Command{
		Use:   "browser",
		Short: "Perform a webpage route capture using a headless browser",
		Long:  `Perform a webpage route capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")
			captureStaticAssets, _ := cmd.Flags().GetBool("capture-static-assets")

			var browserPath *string
			if path, err := cmd.Flags().GetString("browserPath"); err == nil {
				if path != "" {
					browserPath = &path
				}
			} else {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")

			// Extract the routes and links
			report := routecapture.PerformRouteCapture(cmd.Context(), target, common.CaptureMethodBrowser, baseURLsOnly, captureStaticAssets, timeout, minDOMStabalizeTime, false, browserPath, nil, nil, nil)
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
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			baseURLsOnly, _ := cmd.Flags().GetBool("base-urls-only")
			captureStaticAssets, _ := cmd.Flags().GetBool("capture-static-assets")

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
			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")
			proxy, _ := cmd.Flags().GetBool("proxy")
			countries, _ := cmd.Flags().GetStringArray("country")

			var options []browserbase.Option
			if proxy && len(countries) > 0 {
				options = append(options, browserbase.WithProxyCountries(countries))
			} else if proxy {
				options = append(options, browserbase.WithProxy())
			}

			// Extract the routes and links
			report := routecapture.PerformRouteCapture(cmd.Context(), target, common.CaptureMethodBrowserbase, baseURLsOnly, captureStaticAssets, timeout, minDOMStabalizeTime, false, nil, &token, &project, &options)
			a.OutputSignal.Content = report
		},
	}
	browserbaseCaptureCmd.Flags().String("token", "", "Browserbase API token")
	browserbaseCaptureCmd.Flags().String("project", "", "Browserbase project ID")
	browserbaseCaptureCmd.Flags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	browserbaseCaptureCmd.Flags().StringArray("country", []string{}, "List of countries to use for the proxy")
	routeCaptureCmd.AddCommand(browserbaseCaptureCmd)

	a.RootCmd.AddCommand(routeCaptureCmd)
}
