package cmd

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/webserver"
	webserver "github.com/Method-Security/webscan/internal/webserver"
	"github.com/spf13/cobra"
)

// InitWebserverCommand initializes the webserver command for the webscan CLI. This command is used to perform detection tests for web applications.
func (a *WebScan) InitWebserverCommand() {
	webserverCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Perform detection tests for web applications",
		Long:  `Perform detection tests for web applications`,
	}

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

			// Configuration flags
			maxRequests, err := cmd.Flags().GetInt("maxrequests")
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

			// Load configuration
			config := LoadWebserverRatelimitConfig(targets, maxRequests, timespan, timeout)

			// Generate report
			report := webserver.PerformWebserverRatelimit(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	ratelimitCmd.Flags().StringSlice("targets", []string{}, "URL of target")
	ratelimitCmd.Flags().Int("maxrequests", 0, "Number of requests to perform")
	ratelimitCmd.Flags().Int("timespan", 0, "Length of time to send the requests (seconds)")
	ratelimitCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = ratelimitCmd.MarkFlagRequired("targets")
	_ = ratelimitCmd.MarkFlagRequired("maxrequests")

	webserverCmd.AddCommand(ratelimitCmd)

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

			// Configuration flags
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			strategy, err := cmd.Flags().GetString("strategy")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			strategyEnum, err := webscan.NewWebserverProbeStrategyFromString(strings.ToUpper(strategy))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			var browserPath *string
			var minDOMStabalizeTime *int
			if strategyEnum == webscan.WebserverProbeStrategyBrowser {
				bPath, err := cmd.Flags().GetString("browserpath")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				browserPath = &bPath
				domTime, err := cmd.Flags().GetInt("mindomstabalizetime")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				minDOMStabalizeTime = &domTime
			}

			// Load configuration
			config := LoadWebserverProbeConfig(targets, timeout, strategyEnum, browserPath, minDOMStabalizeTime)

			// Generate report
			report, err := webserver.PerformWebserverProbe(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	probeCmd.Flags().StringSlice("targets", []string{}, "Address targets to perform web application probing agains, comma delimited list")
	probeCmd.Flags().Int("timeout", 30, "Timeout limit (seconds)")
	probeCmd.Flags().String("strategy", "REQUEST", "Strategy to use for probing (REQUEST, BROWSER)")
	probeCmd.Flags().String("browserpath", "", "Path to a browser executable")
	probeCmd.Flags().Int("mindomstabalizetime", 5, "Minimum time in seconds to wait for DOM to stabilize")

	_ = probeCmd.MarkFlagRequired("targets")

	webserverCmd.AddCommand(probeCmd)
	a.RootCmd.AddCommand(webserverCmd)
}

func LoadWebserverProbeConfig(targets []string, timeout int, strategy webscan.WebserverProbeStrategy, browserPath *string, minDOMStabalizeTime *int) *webscan.WebserverProbeConfig {
	config := &webscan.WebserverProbeConfig{
		Targets:             targets,
		Timeout:             timeout,
		Strategy:            strategy,
		BrowserPath:         browserPath,
		MinDomStabalizeTime: minDOMStabalizeTime,
	}

	return config
}

func LoadWebserverRatelimitConfig(targets []string, maxRequests int, timespan int, timeout int) *webscan.WebserverRateLimitConfig {
	config := &webscan.WebserverRateLimitConfig{
		Targets:     targets,
		MaxRequests: maxRequests,
		Timespan:    timespan,
		Timeout:     timeout,
	}
	return config
}
