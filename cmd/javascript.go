package cmd

import (
	// Generated
	"github.com/Method-Security/webscan/generated/go/enumerate"
	// Internal
	enumeratejavascript "github.com/Method-Security/webscan/internal/enumerate/javascript"
	javascripthelpers "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	cobra "github.com/spf13/cobra"
)

// InitEnumerateJavascriptCommand registers the 'enumerate javascript' subcommand on the parent.
func (a *WebScan) InitEnumerateJavascriptCommand(enumerateCmd *cobra.Command) {
	enumerateJavascriptCmd := &cobra.Command{
		Use:   "javascript",
		Short: "Analyze a JavaScript bundle for endpoints, secrets and declared chunks",
		Long: `Analyze a JavaScript bundle and the chunks its runtime declares, extracting API endpoints,
configuration and secrets. Lazily-loaded chunks are resolved from the bundle's own chunk manifest
rather than from the DOM, which never references them.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			followChunks, err := cmd.Flags().GetBool("follow-chunks")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fetchSourceMaps, err := cmd.Flags().GetBool("fetch-source-maps")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxArtifacts, err := cmd.Flags().GetInt("max-artifacts")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			analysisWindowBytes, err := cmd.Flags().GetInt("analysis-window-bytes")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			analysisWindowOverlapBytes, err := cmd.Flags().GetInt("analysis-window-overlap-bytes")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ignoreCrossDomainEndpoints, err := cmd.Flags().GetBool("ignore-cross-domain-endpoints")
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
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jitter, err := cmd.Flags().GetInt("jitter")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headerPairs, err := cmd.Flags().GetStringArray("header")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			cookiePairs, err := cmd.Flags().GetStringArray("cookie")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := enumerate.EnumerateJavascriptConfig{
				Target:                     target,
				FollowChunks:               followChunks,
				FetchSourceMaps:            fetchSourceMaps,
				MaxArtifacts:               maxArtifacts,
				AnalysisWindowBytes:        analysisWindowBytes,
				AnalysisWindowOverlapBytes: analysisWindowOverlapBytes,
				IgnoreCrossDomainEndpoints: ignoreCrossDomainEndpoints,
				MaxRedirects:               maxRedirects,
				VerifyTls:                  verifyTLS,
				Timeout:                    max(timeout, 0),
				Sleep:                      max(sleep, 0),
				Jitter:                     max(jitter, 0),
				Threads:                    max(threads, 0),
				UserAgent:                  userAgentPreset,
			}
			config.Headers, err = requesthelpers.ParseHeaderPairs(headerPairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config.Cookies, err = requesthelpers.ParseCookiePairs(cookiePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := enumeratejavascript.PerformJavascriptEnumeration(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Target Flags
	enumerateJavascriptCmd.Flags().String("target", "", "JavaScript bundle URL to analyze")
	// Config Flags
	enumerateJavascriptCmd.Flags().Bool("follow-chunks", true, "Resolve and analyze the lazily-loaded chunks the bundle's runtime declares")
	enumerateJavascriptCmd.Flags().Bool("fetch-source-maps", false, "Fetch the source map published beside each artifact, when one is")
	enumerateJavascriptCmd.Flags().Int("max-artifacts", 50, "Maximum number of declared chunks to fetch (0 = unlimited)")
	enumerateJavascriptCmd.Flags().Int("analysis-window-bytes", javascripthelpers.DefaultWindowBytes, "Bytes of source analyzed per parse")
	enumerateJavascriptCmd.Flags().Int("analysis-window-overlap-bytes", javascripthelpers.DefaultWindowOverlapBytes, "Bytes each analysis window overlaps the previous one")
	enumerateJavascriptCmd.Flags().Bool("ignore-cross-domain-endpoints", true, "Ignore API bases whose host is not the target host or a subdomain of it")
	enumerateJavascriptCmd.Flags().Int("max-redirects", 3, "Maximum number of redirects to follow")
	enumerateJavascriptCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	enumerateJavascriptCmd.Flags().Int("timeout", 60, "Timeout per request in seconds")
	enumerateJavascriptCmd.Flags().Int("threads", 0, "Number of concurrent threads for fetching")
	enumerateJavascriptCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	enumerateJavascriptCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	enumerateJavascriptCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")
	// Authenticated-fetch flags
	enumerateJavascriptCmd.Flags().StringArray("header", []string{}, "Request header as 'Name: Value' (repeatable)")
	enumerateJavascriptCmd.Flags().StringArray("cookie", []string{}, "Cookie as 'name=value' (repeatable)")

	// Mark Required Flags
	_ = enumerateJavascriptCmd.MarkFlagRequired("target")

	// Add Command to 'Enumerate' Command
	enumerateCmd.AddCommand(enumerateJavascriptCmd)
}
