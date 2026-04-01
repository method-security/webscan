package cmd

import (
	// Standard
	"errors"
	"fmt"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverprobe "github.com/Method-Security/webscan/internal/discover"
	discoverapplication "github.com/Method-Security/webscan/internal/discover/application"
	discoverdirectory "github.com/Method-Security/webscan/internal/discover/directory"
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
	discoverpagehelpers "github.com/Method-Security/webscan/internal/discover/page/helpers"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route"
	discoversaas "github.com/Method-Security/webscan/internal/discover/saas/active"
	discoversaashelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"

	// Utils
	nucleihelpers "github.com/Method-Security/webscan/utils/nuclei/helpers"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	cobra "github.com/spf13/cobra"
)

// InitDiscoverCommand initializes the 'discover' command and its subcommands for the CLI.
func (a *WebScan) InitDiscoverCommand() {
	// Discover Command
	// Subcommands: application, directory, page, probe, route, saas
	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Perform various discovery scans",
		Long:  `Perform various discovery scans to identify web applications, directories, routes, and static assets.`,
	}

	// Application Command
	discoverApplicationCmd := &cobra.Command{
		Use:   "application",
		Short: "Perform application discovery against targets",
		Long:  `Perform application fingerprinting to identify web technologies, and services running on target URLs.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Targets flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			resourceType, err := cmd.Flags().GetString("resource-type")
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
			proxy, err := cmd.Flags().GetString("proxy")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if err := nucleihelpers.ValidateProxy(proxy); err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			verboseLogs, err := cmd.Flags().GetBool("verbose-logs")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			globalRateLimit, err := cmd.Flags().GetInt("global-rate-limit")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create config
			config, err := getDiscoverApplicationConfig(targets, resourceType, timeout, threads, proxy, verboseLogs, globalRateLimit)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Generate report
			report, err := discoverapplication.LaunchFingerprintEngine(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverApplicationCmd.Flags().StringSlice("targets", []string{}, "URL targets to perform fingerprinting against")
	// Config Flags
	discoverApplicationCmd.Flags().String("resource-type", "ALL", "Type of resource to fingerprint (e.g., web, api, cms)")
	discoverApplicationCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverApplicationCmd.Flags().Int("threads", 25, "Number of concurrent threads for scanning")
	discoverApplicationCmd.Flags().String("proxy", "", "Optional HTTP proxy URL")
	discoverApplicationCmd.Flags().Bool("verbose-logs", false, "Verbose logs")
	discoverApplicationCmd.Flags().Int("global-rate-limit", 0, "Global rate limit (requests per second, 0 = no limit)")

	// Mark Required Flags
	_ = discoverApplicationCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverApplicationCmd)

	// Directory Command
	discoverDirectoryCmd := &cobra.Command{
		Use:   "directory",
		Short: "Perform directory and file bruteforce discovery",
		Long:  `Perform directory and file bruteforce discovery to identify hidden directories, files, and endpoints on web applications.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Targets flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Directory Discovery Flags
			// Paths flag
			paths, err := cmd.Flags().GetStringSlice("paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			// Wordlist Type flag
			wordlistType, err := cmd.Flags().GetString("wordlist-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			wordlistType = strings.ToUpper(wordlistType)

			// Wordlist Size flag
			wordlistSize, err := cmd.Flags().GetString("wordlist-size")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			wordlistSize = strings.ToUpper(wordlistSize)

			// Validation: at least one input method must be specified
			if len(paths) == 0 && wordlistType == "" {
				a.OutputSignal.AddError(fmt.Errorf("at least one of flags 'paths' or 'wordlist-type' must be provided"))
				return
			}

			// If wordlist-type is specified, wordlist-size is required
			if wordlistType != "" && wordlistSize == "" {
				a.OutputSignal.AddError(fmt.Errorf("when 'wordlist-type' is specified, 'wordlist-size' must also be provided"))
				return
			}
			// HTTP Methods flag
			httpMethodsStr, err := cmd.Flags().GetStringSlice("http-methods")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			httpMethods := make([]common.HttpMethod, 0, len(httpMethodsStr))
			for _, ms := range httpMethodsStr {
				m, err := common.NewHttpMethodFromString(strings.ToUpper(ms))
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				httpMethods = append(httpMethods, m)
			}

			// Config flags
			responseCodes, err := cmd.Flags().GetString("response-codes")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ignoreBaseContentMatch, err := cmd.Flags().GetBool("ignore-base-content-match")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			verifyTLS, err := cmd.Flags().GetBool("verify-tls")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threshold, err := cmd.Flags().GetFloat64("threshold")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxRedirectsBaselineRequest, err := cmd.Flags().GetInt("max-redirects-baseline-request")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxRuntime, err := cmd.Flags().GetInt("max-runtime")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			retries, err := cmd.Flags().GetInt("retries")
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
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(fmt.Errorf("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(fmt.Errorf("jitter must be between 0 and 100"))
				return
			}
			// Set config
			config := getDiscoverDirectoryConfig(targets, paths, wordlistType, wordlistSize, httpMethods, responseCodes, ignoreBaseContentMatch, verifyTLS, threshold, timeout, maxRedirectsBaselineRequest, threads, maxRuntime, retries, sleep, jitter)

			// Generate a report
			rep, err := discoverdirectory.RunDirectoryDiscovery(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = rep
		},
	}
	// Target Flags
	discoverDirectoryCmd.Flags().StringSlice("targets", []string{}, "Targets to be scanned")
	// Directory Discovery Flags
	discoverDirectoryCmd.Flags().StringSlice("paths", []string{}, "Paths to scan")
	discoverDirectoryCmd.Flags().String("wordlist-type", "", "Type of wordlist to use automatically (directories, files)")
	discoverDirectoryCmd.Flags().String("wordlist-size", "", "Size of wordlist to use (TINY, SMALL, MEDIUM, LARGE)")
	discoverDirectoryCmd.Flags().StringSlice("http-methods", []string{"GET"}, "HTTP methods to use (e.g. GET,POST,PUT)")
	// Config Flags
	discoverDirectoryCmd.Flags().String("response-codes", "200-299", "Response codes to consider as valid responses")
	discoverDirectoryCmd.Flags().Bool("ignore-base-content-match", true, "Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect")
	discoverDirectoryCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverDirectoryCmd.Flags().Float64("threshold", 0.25, "Threshold for successful results")
	discoverDirectoryCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverDirectoryCmd.Flags().Int("max-redirects-baseline-request", 10, "Maximum number of redirects to follow for the baseline request")
	discoverDirectoryCmd.Flags().Int("max-runtime", 0, "Maximum time to run the engagement (seconds) (Default is 0, which will run indefinitely)")
	discoverDirectoryCmd.Flags().Int("threads", 0, "Number of threads to use")
	discoverDirectoryCmd.Flags().Int("retries", 0, "Number of times to retry a request if it fails")
	discoverDirectoryCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverDirectoryCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")

	// Mark Required Flags
	_ = discoverDirectoryCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverDirectoryCmd)

	// Page Command
	// Subcommands: capture
	discoverPageCmd := &cobra.Command{
		Use:   "page",
		Short: "Capture and analyze web pages",
		Long:  `Capture and analyze web pages to extract content, take screenshots, and perform various page-level analysis.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			ctx := cmd.Context()

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			var sensitiveContentFingerprintsPath string
			sensitiveContentDetection, err := cmd.Flags().GetBool("sensitive-content-detection")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if sensitiveContentDetection {
				sensitiveContentFingerprintsPath, err = cmd.Flags().GetString("sensitive-content-fingerprints-path")
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
			}
			responseCodes, err := cmd.Flags().GetString("response-codes")
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

			// Get Request Method flag
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
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
			if takeScreenshot && (requestMethodConfig.RequestMethodEnum == common.RequestMethodStandard || requestMethodConfig.RequestMethodEnum == common.RequestMethodBrowserbase) {
				a.OutputSignal.AddError(fmt.Errorf("screenshot flag is not supported for standard or browserbase capture methods"))
				return
			}

			// Set Config
			config := getDiscoverPageConfig(target, sensitiveContentDetection, sensitiveContentFingerprintsPath, responseCodes, maxRedirects, verifyTLS, timeout, takeScreenshot, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Load sensitive content fingerprints if sensitive content detection is enabled and no fingerprints are found, return an error
			var sensitiveContentFingerprints *discover.SensitiveContentFingerprints
			if config.SensitiveContentDetection {
				// Load sensitive content fingerprints
				sensitiveContentFingerprints, err = discoverpagehelpers.LoadSensitiveConentFingerprints(ctx, config.SensitiveContentFingerprintsPath)
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}

				// If no fingerprints are found, return an error
				if sensitiveContentFingerprints == nil || len(sensitiveContentFingerprints.Fingerprints) == 0 {
					a.OutputSignal.AddError(errors.New("no sensitive content fingerprints found"))
					return
				}
			}

			// Generate a report
			report := discoverpage.PerformPageCapture(ctx, config, sensitiveContentFingerprints, requestMethodConfig.BrowserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverPageCmd.Flags().String("target", "", "URL target to capture and analyze")
	// Config Flags
	discoverPageCmd.Flags().Bool("sensitive-content-detection", false, "Enable sensitive content detection")
	discoverPageCmd.Flags().String("sensitive-content-fingerprints-path", "", "Path to a custom sensitive content fingerprints file (uses built-in fingerprints by default)")
	discoverPageCmd.Flags().String("response-codes", "200-299", "Response codes to consider as valid responses")
	discoverPageCmd.Flags().Bool("screenshot", false, "Capture a screenshot of the page")
	discoverPageCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverPageCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverPageCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	// Request Method Flags for all capture subcommands
	discoverPageCmd.Flags().String("request-method", "STANDARD", "Request method to use (standard, headless, browserbase)")
	discoverPageCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverPageCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time to wait for DOM stabilization in seconds")
	discoverPageCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverPageCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverPageCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverPageCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")

	// Mark Required Flags
	_ = discoverPageCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverPageCmd)

	// Probe Command
	discoverProbeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe targets for web application existence",
		Long:  `Probe target URLs to identify if they are running web applications and determine their basic characteristics.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flags
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config flags
			protocol, err := cmd.Flags().GetString("protocol")
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
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(fmt.Errorf("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(fmt.Errorf("jitter must be between 0 and 100"))
				return
			}

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverProbeConfig(targets, protocol, maxRedirects, verifyTLS, timeout, sleep, jitter, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate report
			report, err := discoverprobe.PerformWebProbe(cmd.Context(), config, requestMethodConfig.BrowserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverProbeCmd.Flags().StringSlice("targets", []string{}, "URL targets to probe for web applications")
	discoverProbeCmd.Flags().String("protocol", "", "Protocol to use for the probe (HTTP, HTTPS)")
	// Config Flags
	discoverProbeCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverProbeCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverProbeCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverProbeCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverProbeCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// Request Method Flags
	discoverProbeCmd.Flags().String("request-method", "STANDARD", "Request method to use (standard, headless, browserbase)")
	discoverProbeCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverProbeCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time to wait for DOM stabilization in seconds")
	discoverProbeCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverProbeCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverProbeCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverProbeCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")

	// Mark Required Flags
	_ = discoverProbeCmd.MarkFlagRequired("targets")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverProbeCmd)

	// Route Command
	discoverRouteCmd := &cobra.Command{
		Use:   "route",
		Short: "Discover and analyze web routes",
		Long:  `Discover and analyze web routes to map application structure, identify endpoints, and detect potential vulnerabilities.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config flags
			ignoreBaseURLMatch, err := cmd.Flags().GetBool("ignore-base-url-match")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			collectStaticAssets, err := cmd.Flags().GetBool("collect-static-assets")
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
			threads, err := cmd.Flags().GetInt("threads")
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
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(fmt.Errorf("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(fmt.Errorf("jitter must be between 0 and 100"))
				return
			}

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverRouteConfig(target, ignoreBaseURLMatch, collectStaticAssets, spiderDepth, maxRedirects, verifyTLS, timeout, sleep, jitter, threads, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate a report
			report := discoverroute.PerformRouteCapture(cmd.Context(), config, requestMethodConfig.BrowserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverRouteCmd.Flags().String("target", "", "URL target to discover routes from")
	// Config Flags
	discoverRouteCmd.Flags().Bool("ignore-base-url-match", false, "Add route even if it does not share the target's base URL")
	discoverRouteCmd.Flags().Bool("collect-static-assets", false, "Collect static assets from route discovery")
	discoverRouteCmd.Flags().Int("spider-depth", 3, "Maximum depth for route spidering")
	discoverRouteCmd.Flags().Int("max-redirects", 100, "Maximum number of redirects to follow")
	discoverRouteCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverRouteCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverRouteCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")
	discoverRouteCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverRouteCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// Request Method Flags
	discoverRouteCmd.Flags().String("request-method", "STANDARD", "Request method to use (standard, headless, browserbase)")
	discoverRouteCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverRouteCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time to wait for DOM stabilization in seconds")
	discoverRouteCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverRouteCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverRouteCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverRouteCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")

	// Mark Required Flags
	_ = discoverRouteCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverRouteCmd)

	// SaaS Command
	// Subcommands: active
	discoverSaasCmd := &cobra.Command{
		Use:   "saas",
		Short: "Gather SaaS information given an organization name",
		Long:  `Gather SaaS information given an organization name`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get the Orgs
			orgs, err := cmd.Flags().GetStringSlice("orgs")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get the SaaS and SSO fingerprints from the files
			saasFilePaths, err := cmd.Flags().GetStringSlice("saas-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ssoFilePaths, err := cmd.Flags().GetStringSlice("sso-file-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			saasFingerprints := discoversaashelpers.UnmarshalFingerprints(saasFilePaths, "discover/saas/saas_fingerprints.json")
			ssoFingerprints := discoversaashelpers.UnmarshalFingerprints(ssoFilePaths, "discover/saas/sso_fingerprints.json")
			if len(saasFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SaaS fingerprints found"))
				return
			}
			if len(ssoFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SSO fingerprints found"))
				return
			}

			// Filter SaaS and SSO fingerprints
			saasCompanies, err := cmd.Flags().GetStringSlice("saas-companies")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ssoCompanies, err := cmd.Flags().GetStringSlice("sso-companies")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filteredSaasFingerprints, err := discoversaashelpers.FilterFingerprints(saasCompanies, saasFingerprints)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filteredSsoFingerprints, err := discoversaashelpers.FilterFingerprints(ssoCompanies, ssoFingerprints)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(filteredSaasFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SaaS fingerprints found"))
				return
			}
			if len(filteredSsoFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SSO fingerprints found"))
				return
			}

			// Config
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
			threads, err := cmd.Flags().GetInt("threads")
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
			if jitter > 0 && sleep <= 0 {
				a.OutputSignal.AddError(fmt.Errorf("jitter requires sleep > 0"))
				return
			}
			if jitter < 0 || jitter > 100 {
				a.OutputSignal.AddError(fmt.Errorf("jitter must be between 0 and 100"))
				return
			}

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate Request Method (Only headless and browserbase are supported)
			requestMethodEnum := requestMethodConfig.RequestMethodEnum
			if requestMethodEnum != common.RequestMethodHeadless && requestMethodEnum != common.RequestMethodBrowserbase {
				a.OutputSignal.AddError(errors.New("invalid request method, must be headless or browserbase"))
				return
			}

			// Get the config
			config := getDiscoverSaasConfig(orgs, saasCompanies, ssoCompanies, maxRedirects, verifyTLS, timeout, sleep, jitter, threads, requestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

			// Generate the report
			report, err := discoversaas.LaunchDiscoverSaas(cmd.Context(), config, *filteredSaasFingerprints, *filteredSsoFingerprints, requestMethodConfig.BrowserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverSaasCmd.Flags().StringSlice("orgs", []string{}, "The organization names to use for discovery")
	// Config Flags
	discoverSaasCmd.Flags().StringSlice("saas-file-paths", []string{}, "Files containing SaaS application fingerprints")
	discoverSaasCmd.Flags().StringSlice("sso-file-paths", []string{}, "Files containing SSO application fingerprints")
	discoverSaasCmd.Flags().StringSlice("saas-companies", []string{}, "The specific SaaS companies to use for discovery (Must be present in the SaaS fingerprints file)")
	discoverSaasCmd.Flags().StringSlice("sso-companies", []string{}, "The specific SSO companies to use for discovery (Must be present in the SSO fingerprints file)")
	discoverSaasCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverSaasCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverSaasCmd.Flags().Int("timeout", 30, "Timeout in seconds for the capture")
	discoverSaasCmd.Flags().Int("threads", 0, "Number of concurrent threads for discovery (default: number of CPUs)")
	discoverSaasCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverSaasCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// Request Method Flags for all capture subcommands
	discoverSaasCmd.Flags().String("request-method", "HEADLESS", "Request method (headless, browserbase)")
	discoverSaasCmd.Flags().String("headless-path", "", "Path to a headless browser executable")
	discoverSaasCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time in seconds to wait for DOM to stabilize")
	discoverSaasCmd.Flags().String("browserbase-token", "", "Browserbase API token")
	discoverSaasCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverSaasCmd.Flags().Bool("browserbase-proxy", false, "Instruct Browserbase to use a proxy")
	discoverSaasCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for the proxy")

	_ = discoverSaasCmd.MarkFlagRequired("orgs")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverSaasCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

// getDiscoverApplicationConfig builds the config for application fingerprinting discovery.
func getDiscoverApplicationConfig(targets []string, resource string, timeout int, threads int, proxy string, verboseLogs bool, globalRateLimit int) (*discover.DiscoverApplicationConfig, error) {
	resourceEnum, err := getDiscoverApplicationResourceConfigTypeFromString(resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resource)
	}

	config := &discover.DiscoverApplicationConfig{
		Targets:         targets,
		ResourceType:    &resourceEnum,
		Timeout:         timeout,
		Threads:         threads,
		Proxy:           &proxy,
		VerboseLogs:     verboseLogs,
		GlobalRateLimit: max(0, globalRateLimit),
	}
	return config, nil
}

// getDiscoverPageConfig builds the config for page capture and analysis.
func getDiscoverPageConfig(target string, sensitiveContentDetection bool, sensitiveContentFingerprintsPath string, responseCodes string, maxRedirects int, verifyTLS bool, timeout int, takeScreenshot bool, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverPageConfig {
	config := discover.DiscoverPageConfig{
		Target:                    target,
		ResponseCodes:             responseCodes,
		SensitiveContentDetection: sensitiveContentDetection,
		MaxRedirects:              maxRedirects,
		VerifyTls:                 verifyTLS,
		Timeout:                   max(timeout, 0),
		Screenshot:                takeScreenshot,
		RequestMethod:             requestMethod,
		HeadlessConfig:            headlessConfig,
		BrowserbaseConfig:         browserbaseConfig,
	}
	if sensitiveContentFingerprintsPath != "" {
		config.SensitiveContentFingerprintsPath = &sensitiveContentFingerprintsPath
	}
	return config
}

// getDiscoverProbeConfig builds the config for probe discovery.
func getDiscoverProbeConfig(targets []string, protocol string, maxRedirects int, verifyTLS bool, timeout int, sleep int, jitter int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) *discover.DiscoverProbeConfig {
	config := &discover.DiscoverProbeConfig{
		Targets:           targets,
		MaxRedirects:      maxRedirects,
		VerifyTls:         verifyTLS,
		Timeout:           max(timeout, 0),
		Sleep:             max(sleep, 0),
		Jitter:            max(jitter, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}

	// Set protocol if provided, otherwise leave unset for backward compatibility
	if protocol != "" {
		switch strings.ToUpper(protocol) {
		case "HTTP":
			httpProtocol := common.WebProtocolHttp
			config.Protocol = &httpProtocol
		case "HTTPS":
			httpsProtocol := common.WebProtocolHttps
			config.Protocol = &httpsProtocol
		default:
			// Invalid protocol - will be handled by validation in the probe function
			// For now, leave it unset to maintain existing behavior
		}
	}

	return config
}

// getDiscoverRouteConfig builds the config for route discovery.
func getDiscoverRouteConfig(target string, ignoreBaseURLMatch bool, collectStaticAssets bool, spiderDepth int, maxRedirects int, verifyTLS bool, timeout int, sleep int, jitter int, threads int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverRouteConfig {
	config := discover.DiscoverRouteConfig{
		Target:              target,
		CollectStaticAssets: collectStaticAssets,
		IgnoreBaseUrlMatch:  ignoreBaseURLMatch,
		SpiderDepth:         spiderDepth,
		MaxRedirects:        maxRedirects,
		VerifyTls:           verifyTLS,
		Timeout:             max(timeout, 0),
		Sleep:               max(sleep, 0),
		Jitter:              max(jitter, 0),
		Threads:             max(threads, 0),
		RequestMethod:       requestMethod,
		HeadlessConfig:      headlessConfig,
		BrowserbaseConfig:   browserbaseConfig,
	}
	return config
}

// getDiscoverSaasConfig builds the config for SaaS active discovery.
func getDiscoverSaasConfig(orgs []string, saasCompanies []string, ssoCompanies []string, maxRedirects int, verifyTLS bool, timeout int, sleep int, jitter int, threads int, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverSaasConfig {
	config := discover.DiscoverSaasConfig{
		Orgs:              orgs,
		SaasCompanies:     saasCompanies,
		SsoCompanies:      ssoCompanies,
		MaxRedirects:      maxRedirects,
		VerifyTls:         verifyTLS,
		Timeout:           max(timeout, 0),
		Sleep:             max(sleep, 0),
		Jitter:            max(jitter, 0),
		Threads:           max(threads, 0),
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return config
}

// getDiscoverDirectoryConfig builds the config for directory discovery.
func getDiscoverDirectoryConfig(targets []string, paths []string, wordlistType string, wordlistSize string, httpMethods []common.HttpMethod, responseCodes string, ignoreBaseContentMatch bool, verifyTLS bool, threshold float64, timeout int, maxRedirectsBaselineRequest int, threads int, maxRuntime int, retries int, sleep int, jitter int) discover.DiscoverDirectoryConfig {
	config := discover.DiscoverDirectoryConfig{
		Targets:                     targets,
		Paths:                       paths,
		HttpMethods:                 httpMethods,
		ResponseCodes:               responseCodes,
		IgnoreBaseContentMatch:      ignoreBaseContentMatch,
		VerifyTls:                   verifyTLS,
		Threshold:                   threshold,
		Timeout:                     timeout,
		MaxRedirectsBaselineRequest: maxRedirectsBaselineRequest,
		Threads:                     threads,
		MaxRuntime:                  maxRuntime,
		Retries:                     retries,
		Sleep:                       sleep,
		Jitter:                      jitter,
	}

	// Set wordlist type and size if provided
	if wordlistType != "" {
		wordlistTypeEnum, err := discover.NewWordlistTypeFromString(wordlistType)
		if err != nil {
			// Log warning but continue - the caller already validated that wordlist-type is required
			config.WordlistType = nil
		} else {
			config.WordlistType = &wordlistTypeEnum
		}
	}

	if wordlistSize != "" {
		wordlistSizeEnum, err := discover.NewWordlistSizeFromString(wordlistSize)
		if err != nil {
			config.WordlistSize = nil
		} else {
			config.WordlistSize = &wordlistSizeEnum
		}
	}

	return config
}

func getDiscoverApplicationResourceConfigTypeFromString(resource string) (discover.ApplicationResourceConfigType, error) {
	if resource == "ALL" {
		return discover.ApplicationResourceConfigType{
			ApplicationResourceTypeAll: discover.ApplicationResourceTypeAllAll,
		}, nil
	}
	resourceEnum, err := discover.NewApplicationResourceTypeFromString(resource)
	if err != nil {
		return discover.ApplicationResourceConfigType{}, fmt.Errorf("invalid resource type: %s", resource)
	}
	return discover.ApplicationResourceConfigType{
		ApplicationResourceType: resourceEnum,
	}, nil
}
