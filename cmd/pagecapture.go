package cmd

import (
	"fmt"
	"os"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/internal/pagecapture"
	"github.com/Method-Security/webscan/internal/pagecapture/helpers/browserbase"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitPagecaptureCommand initializes the pagecapture command for the webscan CLI. This command is used to collect
// the HTML of a webpage from a URL target.
func (a *WebScan) InitPagecaptureCommand() {
	pagecaptureCmd := &cobra.Command{
		Use:     "pagecapture",
		Aliases: []string{"capture"},
		Short:   "Perform a webpage capture against a URL target",
		Long:    `Perform a webpage capture against a URL target`,
	}

	pageScreenshotCmd := &cobra.Command{
		Use:   "screenshot",
		Short: "Perform a webpage screenshot and HTML capture against a URL target",
		Long:  `Perform a webpage screenshot and HTML capture against a URL target`,
	}
	pageScreenshotCmd.PersistentFlags().String("target", "", "URL target to perform webpage capture")
	pageScreenshotCmd.PersistentFlags().Int("timeout", 30, "Timeout in seconds for the capture")
	pageScreenshotCmd.PersistentFlags().Int("minDOMStabalizeTime", 5, "Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots")

	browserScreenshotCmd := &cobra.Command{
		Use:   "browser",
		Short: "Perform a fully rendered webpage screenshot and HTML capture capture using a headless browser",
		Long:  `Perform a fully rendered webpage screenshot and HTML capture capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			log := svc1log.FromContext(cmd.Context())

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

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")

			report := pagecapture.PerformScreenshotPageCapture(cmd.Context(), target, common.CaptureMethodBrowser, false, false, timeout, minDOMStabalizeTime, false, browserPath, nil, nil, nil)
			log.Info("Screenshot capture successful", svc1log.SafeParam("target", target))

			a.OutputSignal.Content = report
		},
	}
	browserScreenshotCmd.PersistentFlags().String("browserPath", "", "Path to a browser executable")

	pageScreenshotCmd.AddCommand(browserScreenshotCmd)

	browserbaseScreenshotCmd := &cobra.Command{
		Use:   "browserbase",
		Short: "Perform a fully rendered webpage screenshot and HTML capture using Browserbase",
		Long:  `Perform a fully rendered webpage screenshot and HTML capture using Browserbase. Useful for avoiding bot detection or maintaining stealth`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			countries, _ := cmd.Flags().GetStringArray("country")
			if len(countries) > 0 {
				_ = cmd.MarkFlagRequired("proxy")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			log := svc1log.FromContext(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

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

			report := pagecapture.PerformScreenshotPageCapture(cmd.Context(), target, common.CaptureMethodBrowserbase, false, false, timeout, minDOMStabalizeTime, false, nil, &token, &project, &options)
			log.Info("Screenshot capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = report
		},
	}
	browserbaseScreenshotCmd.Flags().String("token", "", "Browserbase API token")
	browserbaseScreenshotCmd.Flags().String("project", "", "Browserbase project ID")
	browserbaseScreenshotCmd.Flags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	browserbaseScreenshotCmd.Flags().StringArray("country", []string{}, "List of countries to use for the proxy")

	pageScreenshotCmd.AddCommand(browserbaseScreenshotCmd)

	htmlCaptureCmd := &cobra.Command{
		Use:   "html",
		Short: "Perform a webpage HTML capture against a URL target",
		Long:  `Perform a webpage HTML capture against a URL target`,
	}
	htmlCaptureCmd.PersistentFlags().String("target", "", "URL target to perform webpage capture")
	htmlCaptureCmd.PersistentFlags().Int("timeout", 30, "Timeout in seconds for the capture")
	htmlCaptureCmd.PersistentFlags().Int("minDOMStabalizeTime", 5, "Minimum time in seconds to wait for DOM to stabilize, currently only used in screenshots")

	requestCaptureCmd := &cobra.Command{
		Use:   "request",
		Short: "Perform a webpage HTML capture using a basic HTTP/HTTPS request",
		Long:  `Perform a webpage HTML capture using a basic HTTP/HTTPS request`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			log := svc1log.FromContext(cmd.Context())
			insecure, _ := cmd.Flags().GetBool("insecure")
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, _ := cmd.Flags().GetInt("timeout")

			report := pagecapture.PerformHTMLPageCapture(cmd.Context(), target, common.CaptureMethodRequest, false, false, timeout, 0, insecure, nil, nil, nil, nil)
			log.Info("Page capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = report
		},
	}
	requestCaptureCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	htmlCaptureCmd.AddCommand(requestCaptureCmd)

	browserCaptureCmd := &cobra.Command{
		Use:   "browser",
		Short: "Perform a fully rendered webpage HTML capture using a headless browser",
		Long:  `Perform a fully rendered webpage HTML capture using a headless browser`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			log := svc1log.FromContext(cmd.Context())

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

			timeout, _ := cmd.Flags().GetInt("timeout")
			minDOMStabalizeTime, _ := cmd.Flags().GetInt("minDOMStabalizeTime")

			report := pagecapture.PerformHTMLPageCapture(cmd.Context(), target, common.CaptureMethodBrowser, false, false, timeout, minDOMStabalizeTime, false, browserPath, nil, nil, nil)
			log.Info("Page capture successful", svc1log.SafeParam("target", target))

			a.OutputSignal.Content = report
		},
	}
	browserCaptureCmd.PersistentFlags().String("browserPath", "", "Path to a browser executable")
	htmlCaptureCmd.AddCommand(browserCaptureCmd)

	browserbaseCaptureCmd := &cobra.Command{
		Use:   "browserbase",
		Short: "Perform a fully rendered webpage HTML capture using Browserbase",
		Long:  `Perform a fully rendered webpage HTML capture using Browserbase. Useful for avoiding bot detection or maintaining stealth`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			countries, _ := cmd.Flags().GetStringArray("country")
			if len(countries) > 0 {
				_ = cmd.MarkFlagRequired("proxy")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			log := svc1log.FromContext(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

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

			report := pagecapture.PerformHTMLPageCapture(cmd.Context(), target, common.CaptureMethodBrowserbase, false, false, timeout, minDOMStabalizeTime, false, nil, &token, &project, &options)
			log.Info("Page capture successful", svc1log.SafeParam("target", target))
			a.OutputSignal.Content = report
		},
	}
	browserbaseCaptureCmd.Flags().String("token", "", "Browserbase API token")
	browserbaseCaptureCmd.Flags().String("project", "", "Browserbase project ID")
	browserbaseCaptureCmd.Flags().Bool("proxy", false, "Instruct Browserbase to use a proxy")
	browserbaseCaptureCmd.Flags().StringArray("country", []string{}, "List of countries to use for the proxy")

	htmlCaptureCmd.AddCommand(browserbaseCaptureCmd)

	pagecaptureCmd.AddCommand(htmlCaptureCmd)
	pagecaptureCmd.AddCommand(pageScreenshotCmd)
	a.RootCmd.AddCommand(pagecaptureCmd)
}

// TODO: We could likely move this to viper to streamline
func getFlagOrEnvironmentVariable(cmd *cobra.Command, flagName string, environmentVariableName string) (string, error) {
	var value string
	if envVar, exists := os.LookupEnv(environmentVariableName); exists && envVar != "" {
		value = envVar
	} else if flagValue, err := cmd.Flags().GetString(flagName); err == nil && flagValue != "" {
		value = flagValue
	} else {
		return "", fmt.Errorf("no value provided for %s", flagName)
	}

	return value, nil
}
