package cmd

import (
	// Standard
	"errors"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	generalfern "github.com/Method-Security/webscan/generated/go/general"
	general "github.com/Method-Security/webscan/internal/general"

	// Utils
	browserbase "github.com/Method-Security/webscan/utils/request/helpers/headless/browserbase"
	// External
	cobra "github.com/spf13/cobra"
)

// InitGeneralCommand initializes the general command for the webscan CLI. This command is used to perform detection tests for web applications.
func (a *WebScan) InitGeneralCommand() {
	generalCmd := &cobra.Command{
		Use:   "general",
		Short: "Perform detection tests for web applications",
		Long:  `Perform detection tests for web applications`,
	}

	probeCmd := &cobra.Command{
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
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Request method
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
				tokenStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "token", "BROWSERBASE_TOKEN")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				projectStr, err := browserbase.GetFlagOrEnvironmentVariable(cmd, "project", "BROWSERBASE_PROJECT")
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
			config := LoadGeneralProbeConfig(targets, maxRedirects, onlyHTTPS, timeout, requestMethodEnum, headlessConfig, browserbaseConfig)

			// Generate report
			report, err := general.PerformGeneralProbe(cmd.Context(), config, browserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	probeCmd.Flags().StringSlice("targets", []string{}, "Address targets to perform web application probing against, comma delimited list")
	probeCmd.Flags().Bool("only-https", false, "Only perform probing over HTTPS")
	probeCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	probeCmd.Flags().Int("timeout", 30, "Timeout limit (Seconds)")

	_ = probeCmd.MarkFlagRequired("targets")

	generalCmd.AddCommand(probeCmd)

	ratelimitCmd := &cobra.Command{
		Use:   "ratelimit",
		Short: "Perform detection tests for rate limiting",
		Long:  `Perform detection tests for rate limiting`,
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
			timespan, err := cmd.Flags().GetInt("timespan")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Request method flag
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
			if requestMethodEnum != common.RequestMethodStandard {
				a.OutputSignal.AddError(errors.New("only standard request method is supported"))
				return
			}

			// Set Config
			config := LoadGeneralRatelimitConfig(targets, maxRequests, timespan, timeout)

			// Generate report
			report := general.PerformGeneralRatelimit(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	ratelimitCmd.Flags().StringSlice("targets", []string{}, "URL of target")
	ratelimitCmd.Flags().Int("max-requests", 0, "Number of requests to perform")
	ratelimitCmd.Flags().Int("timespan", 0, "Length of time to send the requests (Seconds)")
	ratelimitCmd.Flags().Int("timeout", 30, "Timeout per request (Seconds)")

	_ = ratelimitCmd.MarkFlagRequired("targets")
	_ = ratelimitCmd.MarkFlagRequired("max-requests")

	generalCmd.AddCommand(ratelimitCmd)
	a.RootCmd.AddCommand(generalCmd)
}

func LoadGeneralProbeConfig(targets []string, maxRedirects int, onlyHTTPS bool, timeout int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessConfig, browserbaseConfig *common.BrowserbaseConfig) *generalfern.GeneralProbeConfig {
	config := &generalfern.GeneralProbeConfig{
		Targets:           targets,
		MaxRedirects:      maxRedirects,
		OnlyHttps:         onlyHTTPS,
		Timeout:           max(timeout, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}

	return config
}

func LoadGeneralRatelimitConfig(targets []string, maxRequests int, timespan int, timeout int) *generalfern.GeneralRateLimitConfig {
	config := &generalfern.GeneralRateLimitConfig{
		Targets:     targets,
		MaxRequests: maxRequests,
		Timespan:    max(timespan, 0),
		Timeout:     max(timeout, 0),
	}
	return config
}
