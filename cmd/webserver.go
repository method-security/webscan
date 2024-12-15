package cmd

import (
	webscan "github.com/Method-Security/webscan/generated/go/webserver"
	webserver "github.com/Method-Security/webscan/internal/webserver"
	"github.com/spf13/cobra"
)

// InitWebserverCommand initializes the webserver command for the webscan CLI. This command is used to perform detection tests for web applications.
func (a *WebScan) InitWebserverCommand() {
	a.WebserverCmd = &cobra.Command{
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

	a.WebserverCmd.AddCommand(ratelimitCmd)

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

			// Load configuration
			config := LoadWebserverProbeConfig(targets, timeout)

			// Generate report
			report := webserver.PerformWebserverProbe(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	probeCmd.Flags().StringSlice("targets", []string{}, "Address targets to perform web application probing agains, comma delimited list")
	probeCmd.Flags().Int("timeout", 30, "Timeout limit (seconds)")

	_ = probeCmd.MarkFlagRequired("targets")

	a.WebserverCmd.AddCommand(probeCmd)

	headergrabCmd := &cobra.Command{
		Use:   "headergrab",
		Short: "Grab the headers of the webserver",
		Long:  `Grab the headers of the webserver`,
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

			// Load configuration
			config := LoadWebserverHeadergrabConfig(targets, timeout)

			// Generate report
			report := webserver.PerformWebserverHeadergrab(cmd.Context(), config)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}

			a.OutputSignal.Content = report
		},
	}

	headergrabCmd.Flags().StringSlice("targets", []string{}, "URL of target")
	headergrabCmd.Flags().Int("timeout", 30, "Timeout per request (seconds)")

	_ = headergrabCmd.MarkFlagRequired("targets")

	a.WebserverCmd.AddCommand(headergrabCmd)

	a.RootCmd.AddCommand(a.WebserverCmd)
}

func LoadWebserverProbeConfig(targets []string, timeout int) *webscan.WebserverProbeConfig {
	config := &webscan.WebserverProbeConfig{
		Targets: targets,
		Timeout: timeout,
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

func LoadWebserverHeadergrabConfig(targets []string, timeout int) *webscan.WebserverHeadergrabConfig {
	config := &webscan.WebserverHeadergrabConfig{
		Targets: targets,
		Timeout: timeout,
	}
	return config
}
