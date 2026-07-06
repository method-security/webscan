package cmd

import (
	// Standard
	"encoding/base64"
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
	discoverrequest "github.com/Method-Security/webscan/internal/discover/request"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route"
	discoversaas "github.com/Method-Security/webscan/internal/discover/saas/active"
	discoversaashelpers "github.com/Method-Security/webscan/internal/discover/saas/active/helpers"
	discoverwitness "github.com/Method-Security/webscan/internal/discover/witness"
	discoverwordlist "github.com/Method-Security/webscan/internal/discover/wordlist"

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

	// General Discover Flags
	discoverCmd.PersistentFlags().Bool("ignore-cross-domain-redirects", true, "If true, do not follow redirects to a different domain and treat them as errors")

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
			globalTimeout, err := cmd.Flags().GetInt("global-timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			templatePaths, err := cmd.Flags().GetStringSlice("template-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Create config
			config, err := getDiscoverApplicationConfig(targets, resourceType, templatePaths, timeout, threads, proxy, verboseLogs, globalRateLimit, globalTimeout, userAgentPreset)
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
	discoverApplicationCmd.Flags().StringSlice("template-paths", []string{}, "Custom nuclei template file or directory paths; overrides --resource-type when set")
	discoverApplicationCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverApplicationCmd.Flags().Int("threads", 25, "Number of concurrent threads for scanning")
	discoverApplicationCmd.Flags().String("proxy", "", "Optional HTTP proxy URL")
	discoverApplicationCmd.Flags().Bool("verbose-logs", false, "Verbose logs")
	discoverApplicationCmd.Flags().Int("global-rate-limit", 10, "Global rate limit in requests per second")
	discoverApplicationCmd.Flags().Int("global-timeout", 0, "Maximum total scan time in seconds")
	discoverApplicationCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

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
			omitStandardResponses, err := cmd.Flags().GetBool("omit-standard-responses")
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
			ignoreCrossDomainRedirects, err := cmd.Flags().GetBool("ignore-cross-domain-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set config
			config := getDiscoverDirectoryConfig(targets, paths, wordlistType, wordlistSize, httpMethods, responseCodes, ignoreBaseContentMatch, omitStandardResponses, verifyTLS, threshold, timeout, ignoreCrossDomainRedirects, maxRedirectsBaselineRequest, threads, maxRuntime, retries, sleep, jitter, userAgentPreset)

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
	discoverDirectoryCmd.Flags().String("wordlist-type", "", "Type of wordlist to use automatically (DIRECTORIES, FILES)")
	discoverDirectoryCmd.Flags().String("wordlist-size", "", "Size of wordlist to use (TINY, SMALL, MEDIUM, LARGE)")
	discoverDirectoryCmd.Flags().StringSlice("http-methods", []string{"GET"}, "HTTP methods to use (e.g. GET,POST,PUT)")
	// Config Flags
	discoverDirectoryCmd.Flags().String("response-codes", "200-299", "Response codes to consider as valid responses")
	discoverDirectoryCmd.Flags().Bool("ignore-base-content-match", true, "Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect")
	discoverDirectoryCmd.Flags().Bool("omit-standard-responses", true, "Omits responses whose body matches a standard web page error (e.g. soft 404s, WAF blocks, generic server errors), even if the status code is allowed")
	discoverDirectoryCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverDirectoryCmd.Flags().Float64("threshold", 0.25, "Threshold for successful results")
	discoverDirectoryCmd.Flags().Int("timeout", 20, "Timeout per request in seconds")
	discoverDirectoryCmd.Flags().Int("max-redirects-baseline-request", 10, "Maximum number of redirects to follow for the baseline request")
	discoverDirectoryCmd.Flags().Int("max-runtime", 650, "Maximum time to run the engagement in seconds")
	discoverDirectoryCmd.Flags().Int("threads", 25, "Number of threads to use")
	discoverDirectoryCmd.Flags().Int("retries", 0, "Number of times to retry a request if it fails")
	discoverDirectoryCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverDirectoryCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// User Agent Flag
	discoverDirectoryCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

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

			ignoreCrossDomainRedirects, err := cmd.Flags().GetBool("ignore-cross-domain-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
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

			// Validate user-agent compatibility with the chosen request method
			if err := requesthelpers.ValidateUserAgentWithRequestMethod(userAgentPreset, requestMethodConfig.RequestMethodEnum, cmd.Flags().Changed("user-agent")); err != nil {
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

			// Authenticated-capture flags
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
			localStoragePairs, err := cmd.Flags().GetStringArray("local-storage")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sessionStoragePairs, err := cmd.Flags().GetStringArray("session-storage")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverPageConfig(target, sensitiveContentDetection, sensitiveContentFingerprintsPath, responseCodes, maxRedirects, verifyTLS, timeout, ignoreCrossDomainRedirects, takeScreenshot, userAgentPreset, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)
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
			config.LocalStorage, err = requesthelpers.ParseFormDataPairs(localStoragePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config.SessionStorage, err = requesthelpers.ParseFormDataPairs(sessionStoragePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

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
	discoverPageCmd.Flags().Bool("sensitive-content-detection", true, "Enable sensitive content detection")
	discoverPageCmd.Flags().String("sensitive-content-fingerprints-path", "", "Path to a custom sensitive content fingerprints file")
	discoverPageCmd.Flags().String("response-codes", "200-299", "Response codes to consider as valid responses")
	discoverPageCmd.Flags().Bool("screenshot", false, "Capture a screenshot of the page")
	discoverPageCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverPageCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverPageCmd.Flags().Int("timeout", 180, "Timeout per request in seconds")
	// User Agent Flag
	discoverPageCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")
	// Request Method Flags for all capture subcommands
	discoverPageCmd.Flags().String("request-method", "HEADLESS", "Request method to use (standard, headless, browserbase)")
	discoverPageCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverPageCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time to wait for DOM stabilization in seconds")
	discoverPageCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverPageCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverPageCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverPageCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")
	// Authenticated-capture flags
	discoverPageCmd.Flags().StringArray("header", []string{}, "Request header for authenticated capture as 'Name: Value' (repeatable; missing colon errors; repeated names are case-insensitively comma-joined per RFC 7230 §3.2.2)")
	discoverPageCmd.Flags().StringArray("cookie", []string{}, "Cookie for authenticated capture as 'name=value' (repeatable; missing equals errors)")
	discoverPageCmd.Flags().StringArray("local-storage", []string{}, "localStorage entry as 'key=value' injected before page load (repeatable, headless only)")
	discoverPageCmd.Flags().StringArray("session-storage", []string{}, "sessionStorage entry as 'key=value' injected before page load (repeatable, headless only)")

	// Mark Required Flags
	_ = discoverPageCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverPageCmd)

	// Request Command
	discoverRequestCmd := &cobra.Command{
		Use:   "request",
		Short: "Send a freeform HTTP request to a target",
		Long:  `Send a freeform HTTP request to a target URL and capture the full HTTP response along with TLS certificate details.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// HTTP Method flag
			httpMethodStr, err := cmd.Flags().GetString("http-method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			httpMethod, err := common.NewHttpMethodFromString(strings.ToUpper(httpMethodStr))
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Header flag (repeated)
			headerPairs, err := cmd.Flags().GetStringArray("header")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headers, err := requesthelpers.ParseHeaderPairs(headerPairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// JSON body flags. json-body-base64 is transport-safe for callers that
			// construct commands through an intermediate shell string; when supplied,
			// decode it into JsonBody and preserve the decoded JSON in the report.
			jsonBodyStr, err := cmd.Flags().GetString("json-body")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			jsonBodyBase64Str, err := cmd.Flags().GetString("json-body-base64")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if jsonBodyStr != "" && jsonBodyBase64Str != "" {
				a.OutputSignal.AddError(fmt.Errorf("only one of --json-body or --json-body-base64 may be provided"))
				return
			}
			var jsonBody *string
			var jsonBodyBase64 *string
			if jsonBodyBase64Str != "" {
				decoded, decodeErr := base64.StdEncoding.DecodeString(jsonBodyBase64Str)
				if decodeErr != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid --json-body-base64 value: %w", decodeErr))
					return
				}
				decodedStr := string(decoded)
				jsonBody = &decodedStr
				jsonBodyBase64 = &jsonBodyBase64Str
			} else if jsonBodyStr != "" {
				jsonBody = &jsonBodyStr
			}

			// Text body flag
			textBodyStr, err := cmd.Flags().GetString("text-body")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var textBody *string
			if textBodyStr != "" {
				textBody = &textBodyStr
			}

			// Form data flag (repeated)
			formDataPairs, err := cmd.Flags().GetStringArray("form-data")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			formData, err := requesthelpers.ParseFormDataPairs(formDataPairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Multipart file upload flag (repeated)
			filePairs, err := cmd.Flags().GetStringArray("file")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			files, err := parseDiscoverRequestFiles(filePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Raw binary body flags
			binaryBodyStr, err := cmd.Flags().GetString("binary-body")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var binaryBody *string
			if binaryBodyStr != "" {
				binaryBody = &binaryBodyStr
			}
			binaryBodyMimeStr, err := cmd.Flags().GetString("binary-body-mime-type")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var binaryBodyMime *string
			if binaryBodyMimeStr != "" {
				binaryBodyMime = &binaryBodyMimeStr
			}

			// Config flags
			maxRedirects, err := cmd.Flags().GetInt("max-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			followRedirects, err := cmd.Flags().GetBool("follow-redirects")
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
			ignoreCrossDomainRedirects, err := cmd.Flags().GetBool("ignore-cross-domain-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// If follow-redirects is false, set maxRedirects to 0
			if !followRedirects {
				maxRedirects = 0
			}

			// Build config
			config := discover.DiscoverRequestConfig{
				Target:                     target,
				HttpMethod:                 httpMethod,
				Headers:                    headers,
				JsonBody:                   jsonBody,
				JsonBodyBase64:             jsonBodyBase64,
				TextBody:                   textBody,
				FormData:                   formData,
				Files:                      files,
				BinaryBody:                 binaryBody,
				BinaryBodyMimeType:         binaryBodyMime,
				MaxRedirects:               maxRedirects,
				FollowRedirects:            followRedirects,
				VerifyTls:                  verifyTLS,
				Timeout:                    timeout,
				UserAgent:                  userAgentPreset,
				IgnoreCrossDomainRedirects: ignoreCrossDomainRedirects,
			}

			// Generate report
			report := discoverrequest.PerformRequest(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverRequestCmd.Flags().String("target", "", "URL to send the HTTP request to")
	// Request Flags
	discoverRequestCmd.Flags().String("http-method", "GET", "HTTP method (GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS)")
	discoverRequestCmd.Flags().StringArray("header", []string{}, "Request header as 'Name: Value' (repeatable; each value must contain a colon; repeated names are case-insensitively comma-joined per RFC 7230 §3.2.2 — e.g. two --header \"Accept: application/json\" and --header \"Accept: text/html\" send Accept: application/json, text/html)")
	discoverRequestCmd.Flags().String("json-body", "", "Request body as JSON string")
	discoverRequestCmd.Flags().String("json-body-base64", "", "Request body as base64-encoded JSON string")
	discoverRequestCmd.Flags().String("text-body", "", "Request body as plain text")
	discoverRequestCmd.Flags().StringArray("form-data", []string{}, "Form data as 'key=value' (repeatable; missing equals errors)")
	discoverRequestCmd.Flags().StringArray("file", []string{}, "Multipart file part as 'fieldName|fileName|contentType|base64' (repeatable; contentType may be empty)")
	discoverRequestCmd.Flags().String("binary-body", "", "Raw request body as base64-encoded bytes")
	discoverRequestCmd.Flags().String("binary-body-mime-type", "", "Content-Type for --binary-body (default application/octet-stream)")
	// Config Flags
	discoverRequestCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverRequestCmd.Flags().Bool("follow-redirects", true, "Follow HTTP redirects")
	discoverRequestCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates")
	discoverRequestCmd.Flags().Int("timeout", 30, "Request timeout in seconds")
	// User Agent Flag
	discoverRequestCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

	// Mark Required Flags
	_ = discoverRequestCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverRequestCmd)

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
			ignoreCrossDomainRedirects, err := cmd.Flags().GetBool("ignore-cross-domain-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate user-agent compatibility with the chosen request method
			if err := requesthelpers.ValidateUserAgentWithRequestMethod(userAgentPreset, requestMethodConfig.RequestMethodEnum, cmd.Flags().Changed("user-agent")); err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverProbeConfig(targets, protocol, maxRedirects, verifyTLS, timeout, sleep, jitter, ignoreCrossDomainRedirects, userAgentPreset, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

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
	// User Agent Flag
	discoverProbeCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")
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
			ignoreCrossDomain, err := cmd.Flags().GetBool("ignore-cross-domain")
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

			// Get User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Request Method flags
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate user-agent compatibility with the chosen request method
			if err := requesthelpers.ValidateUserAgentWithRequestMethod(userAgentPreset, requestMethodConfig.RequestMethodEnum, cmd.Flags().Changed("user-agent")); err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get JS route enhancement flags
			bundleURLs, err := cmd.Flags().GetStringSlice("bundle-urls")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fetchSourceMaps, err := cmd.Flags().GetBool("fetch-source-maps")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxBundles, err := cmd.Flags().GetInt("max-bundles")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Authenticated-crawl flags
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
			localStoragePairs, err := cmd.Flags().GetStringArray("local-storage")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sessionStoragePairs, err := cmd.Flags().GetStringArray("session-storage")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverRouteConfig(target, ignoreCrossDomain, collectStaticAssets, spiderDepth, maxRedirects, verifyTLS, timeout, sleep, jitter, threads, userAgentPreset, requestMethodConfig.RequestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig, bundleURLs, fetchSourceMaps, maxBundles)
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
			config.LocalStorage, err = requesthelpers.ParseFormDataPairs(localStoragePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config.SessionStorage, err = requesthelpers.ParseFormDataPairs(sessionStoragePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate a report
			report := discoverroute.PerformRouteCapture(cmd.Context(), config, requestMethodConfig.BrowserbaseSecrets)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverRouteCmd.Flags().String("target", "", "URL target to discover routes from")
	// Config Flags
	discoverRouteCmd.Flags().Bool("ignore-cross-domain", true, "Ignore routes that do not share the target's base URL")
	discoverRouteCmd.Flags().Bool("collect-static-assets", false, "Collect static assets from route discovery")
	discoverRouteCmd.Flags().Int("spider-depth", 1, "Maximum depth for route spidering")
	discoverRouteCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverRouteCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverRouteCmd.Flags().Int("timeout", 90, "Timeout per request in seconds")
	discoverRouteCmd.Flags().Int("threads", 0, "Number of concurrent threads for scanning")
	discoverRouteCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverRouteCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// User Agent Flag
	discoverRouteCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")
	// Request Method Flags
	discoverRouteCmd.Flags().String("request-method", "HEADLESS", "Request method to use (standard, headless, browserbase)")
	discoverRouteCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverRouteCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time to wait for DOM stabilization in seconds")
	discoverRouteCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverRouteCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverRouteCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverRouteCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")
	// JS route discovery enhancement flags
	discoverRouteCmd.Flags().StringSlice("bundle-urls", []string{}, "Explicit JS bundle URLs to scan for routes")
	discoverRouteCmd.Flags().Bool("fetch-source-maps", true, "Fetch and scan source maps for additional routes")
	discoverRouteCmd.Flags().Int("max-bundles", -1, "Maximum number of JS bundles to process (-1 = unlimited, 0 = disabled)")
	// Authenticated-crawl flags
	discoverRouteCmd.Flags().StringArray("header", []string{}, "Request header for authenticated crawl as 'Name: Value' (repeatable; missing colon errors; repeated names are case-insensitively comma-joined per RFC 7230 §3.2.2)")
	discoverRouteCmd.Flags().StringArray("cookie", []string{}, "Cookie for authenticated crawl as 'name=value' (repeatable; missing equals errors)")
	discoverRouteCmd.Flags().StringArray("local-storage", []string{}, "localStorage entry as 'key=value' injected before page load (repeatable, headless only)")
	discoverRouteCmd.Flags().StringArray("session-storage", []string{}, "sessionStorage entry as 'key=value' injected before page load (repeatable, headless only)")

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

			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Validate user-agent compatibility with the chosen request method
			if err := requesthelpers.ValidateUserAgentWithRequestMethod(userAgentPreset, requestMethodEnum, cmd.Flags().Changed("user-agent")); err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get the config
			config := getDiscoverSaasConfig(orgs, saasCompanies, ssoCompanies, maxRedirects, verifyTLS, timeout, sleep, jitter, threads, userAgentPreset, requestMethodEnum, requestMethodConfig.HeadlessConfig, requestMethodConfig.BrowserbaseConfig)

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
	discoverSaasCmd.Flags().Int("timeout", 90, "Timeout in seconds for the capture")
	discoverSaasCmd.Flags().Int("threads", 25, "Number of concurrent threads for discovery")
	discoverSaasCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverSaasCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	discoverSaasCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")
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

	// Wordlist Command
	discoverWordlistCmd := &cobra.Command{
		Use:   "wordlist",
		Short: "Generate a wordlist from web content (CeWL-style)",
		Long:  `Crawl a target website and extract unique words from page content to build a custom wordlist, similar to CeWL.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Get Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config flags
			minWordLength, err := cmd.Flags().GetInt("min-word-length")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			spiderDepth, err := cmd.Flags().GetInt("spider-depth")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			includeMetadata, err := cmd.Flags().GetBool("include-metadata")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			includeComments, err := cmd.Flags().GetBool("include-comments")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			includeAltText, err := cmd.Flags().GetBool("include-alt-text")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ignoreCrossDomain, err := cmd.Flags().GetBool("ignore-cross-domain")
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

			// Get User Agent flag
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set Config
			config := getDiscoverWordlistConfig(target, minWordLength, spiderDepth, includeMetadata, includeComments, includeAltText, ignoreCrossDomain, verifyTLS, timeout, threads, sleep, jitter, userAgentPreset)

			// Generate a report
			report := discoverwordlist.PerformWordlistCapture(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}
	// Target Flags
	discoverWordlistCmd.Flags().String("target", "", "URL target to crawl for wordlist generation")
	// Config Flags
	discoverWordlistCmd.Flags().Int("min-word-length", 5, "Minimum word length to include in wordlist")
	discoverWordlistCmd.Flags().Int("spider-depth", 2, "Maximum depth for web spidering")
	discoverWordlistCmd.Flags().Bool("include-metadata", false, "Include words from meta tag content")
	discoverWordlistCmd.Flags().Bool("include-comments", false, "Include words from HTML comments")
	discoverWordlistCmd.Flags().Bool("include-alt-text", false, "Include words from image alt attributes")
	discoverWordlistCmd.Flags().Bool("ignore-cross-domain", true, "Ignore links that lead to a different domain")
	discoverWordlistCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverWordlistCmd.Flags().Int("timeout", 30, "Timeout per request in seconds")
	discoverWordlistCmd.Flags().Int("threads", 5, "Number of concurrent threads for crawling")
	discoverWordlistCmd.Flags().Int("sleep", 0, "Number of seconds to sleep between requests")
	discoverWordlistCmd.Flags().Int("jitter", 0, "Jitter percentage (0-100) to apply random variance to sleep delay")
	// User Agent Flag
	discoverWordlistCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")

	// Mark Required Flags
	_ = discoverWordlistCmd.MarkFlagRequired("target")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverWordlistCmd)

	// Witness Command
	discoverWitnessCmd := &cobra.Command{
		Use:   "witness",
		Short: "Single-pass web witness: screenshot, HTTP capture, favicon, tech fingerprinting, and TLS extraction",
		Long:  `Perform a single-pass web witness scan: navigate to each target URL, capture a screenshot, extract HTTP metadata, fetch favicons, run Wappalyzer technology fingerprinting, optionally run Nuclei templates, and extract TLS certificates.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			ctx := cmd.Context()

			// Target flags (mutually exclusive, one required)
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			targetsFile, err := cmd.Flags().GetString("targets-file")
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
			takeScreenshot, err := cmd.Flags().GetBool("screenshot")
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
			ignoreCrossDomainRedirects, err := cmd.Flags().GetBool("ignore-cross-domain-redirects")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// User agent and request method
			userAgentPreset, err := requesthelpers.GetUserAgentFlag(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			requestMethodConfig, err := requesthelpers.GetRequestMethodFlags(cmd)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if err := requesthelpers.ValidateUserAgentWithRequestMethod(userAgentPreset, requestMethodConfig.RequestMethodEnum, cmd.Flags().Changed("user-agent")); err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Screenshot requires headless
			if takeScreenshot && (requestMethodConfig.RequestMethodEnum == common.RequestMethodStandard || requestMethodConfig.RequestMethodEnum == common.RequestMethodBrowserbase) {
				a.OutputSignal.AddError(fmt.Errorf("screenshot flag is not supported for standard or browserbase capture methods"))
				return
			}

			// Authenticated-capture flags
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
			localStoragePairs, err := cmd.Flags().GetStringArray("local-storage")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sessionStoragePairs, err := cmd.Flags().GetStringArray("session-storage")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			headers, err := requesthelpers.ParseHeaderPairs(headerPairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			cookies, err := requesthelpers.ParseCookiePairs(cookiePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			localStorageMap, err := requesthelpers.ParseFormDataPairs(localStoragePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sessionStorageMap, err := requesthelpers.ParseFormDataPairs(sessionStoragePairs)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Nuclei flags
			nucleiTemplatePaths, err := cmd.Flags().GetStringSlice("nuclei-template-paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			nucleiThreads, err := cmd.Flags().GetInt("nuclei-threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Build config
			config := discover.DiscoverWitnessConfig{
				SensitiveContentDetection:  sensitiveContentDetection,
				ResponseCodes:              responseCodes,
				Screenshot:                 takeScreenshot,
				MaxRedirects:               max(maxRedirects, 0),
				VerifyTls:                  verifyTLS,
				Timeout:                    max(timeout, 0),
				IgnoreCrossDomainRedirects: ignoreCrossDomainRedirects,
				UserAgent:                  userAgentPreset,
				RequestMethod:              requestMethodConfig.RequestMethodEnum,
				HeadlessConfig:             requestMethodConfig.HeadlessConfig,
				BrowserbaseConfig:          requestMethodConfig.BrowserbaseConfig,
				Headers:                    headers,
				Cookies:                    cookies,
				LocalStorage:               localStorageMap,
				SessionStorage:             sessionStorageMap,
				NucleiTemplatePaths:        nucleiTemplatePaths,
				NucleiThreads:              nucleiThreads,
			}
			if target != "" {
				config.Target = &target
			}
			if targetsFile != "" {
				config.TargetsFile = &targetsFile
			}
			if sensitiveContentFingerprintsPath != "" {
				config.SensitiveContentFingerprintsPath = &sensitiveContentFingerprintsPath
			}

			// Load sensitive content fingerprints if needed
			if config.SensitiveContentDetection {
				scFingerprints, scErr := discoverpagehelpers.LoadSensitiveConentFingerprints(ctx, config.SensitiveContentFingerprintsPath)
				if scErr != nil {
					a.OutputSignal.AddError(scErr)
					return
				}
				if scFingerprints == nil || len(scFingerprints.Fingerprints) == 0 {
					a.OutputSignal.AddError(errors.New("no sensitive content fingerprints found"))
					return
				}
			}

			// Generate report
			report, err := discoverwitness.RunWitness(ctx, config, requestMethodConfig.BrowserbaseSecrets)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	// Target Flags (mutually exclusive, one required)
	discoverWitnessCmd.Flags().String("target", "", "Single URL target for witness scan")
	discoverWitnessCmd.Flags().String("targets-file", "", "File containing one URL per line for witness scan")
	discoverWitnessCmd.MarkFlagsMutuallyExclusive("target", "targets-file")
	discoverWitnessCmd.MarkFlagsOneRequired("target", "targets-file")
	// Config Flags
	discoverWitnessCmd.Flags().Bool("sensitive-content-detection", true, "Enable sensitive content detection")
	discoverWitnessCmd.Flags().String("sensitive-content-fingerprints-path", "", "Path to a custom sensitive content fingerprints file")
	discoverWitnessCmd.Flags().String("response-codes", "200-299", "Response codes to consider as valid responses")
	discoverWitnessCmd.Flags().Bool("screenshot", false, "Capture a screenshot of each page (headless only)")
	discoverWitnessCmd.Flags().Int("max-redirects", 10, "Maximum number of redirects to follow")
	discoverWitnessCmd.Flags().Bool("verify-tls", false, "Verify TLS certificates when making HTTPS requests")
	discoverWitnessCmd.Flags().Int("timeout", 180, "Timeout per request in seconds")
	// User Agent Flag
	discoverWitnessCmd.Flags().String("user-agent", "RANDOM", "User-Agent preset (RANDOM, CHROME, FIREFOX, SAFARI, EDGE)")
	// Request Method Flags
	discoverWitnessCmd.Flags().String("request-method", "HEADLESS", "Request method to use (standard, headless, browserbase)")
	discoverWitnessCmd.Flags().String("headless-path", "", "Path to headless browser executable")
	discoverWitnessCmd.Flags().Int("min-dom-stabalize-time", 20, "Minimum time to wait for DOM stabilization in seconds")
	discoverWitnessCmd.Flags().String("browserbase-token", "", "Browserbase API token for cloud browser access")
	discoverWitnessCmd.Flags().String("browserbase-project", "", "Browserbase project ID")
	discoverWitnessCmd.Flags().Bool("browserbase-proxy", false, "Use Browserbase proxy for requests")
	discoverWitnessCmd.Flags().StringSlice("browserbase-countries", []string{}, "List of countries to use for Browserbase proxy")
	// Authenticated-capture flags
	discoverWitnessCmd.Flags().StringArray("header", []string{}, "Request header for authenticated capture as 'Name: Value' (repeatable)")
	discoverWitnessCmd.Flags().StringArray("cookie", []string{}, "Cookie for authenticated capture as 'name=value' (repeatable)")
	discoverWitnessCmd.Flags().StringArray("local-storage", []string{}, "localStorage entry as 'key=value' injected before page load (repeatable, headless only)")
	discoverWitnessCmd.Flags().StringArray("session-storage", []string{}, "sessionStorage entry as 'key=value' injected before page load (repeatable, headless only)")
	// Nuclei Flags
	discoverWitnessCmd.Flags().StringSlice("nuclei-template-paths", []string{}, "Nuclei template paths to run against targets (leave empty to skip Nuclei)")
	discoverWitnessCmd.Flags().Int("nuclei-threads", 25, "Number of concurrent Nuclei threads")

	// Add Command to 'Discover' Command
	discoverCmd.AddCommand(discoverWitnessCmd)

	// Add Command to Root Command
	a.RootCmd.AddCommand(discoverCmd)
}

// parseDiscoverRequestFiles parses repeated --file values formatted as
// 'fieldName|fileName|contentType|base64' into multipart RequestFile parts.
// contentType may be empty (e.g. 'field|name.txt||<base64>').
func parseDiscoverRequestFiles(pairs []string) ([]*discover.RequestFile, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	files := make([]*discover.RequestFile, 0, len(pairs))
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "|", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid --file %q: expected 'fieldName|fileName|contentType|base64'", pair)
		}
		fieldName := strings.TrimSpace(parts[0])
		fileName := strings.TrimSpace(parts[1])
		contentType := strings.TrimSpace(parts[2])
		contentBase64 := strings.TrimSpace(parts[3])
		if fieldName == "" || fileName == "" || contentBase64 == "" {
			return nil, fmt.Errorf("invalid --file %q: fieldName, fileName, and base64 content are required", pair)
		}
		file := &discover.RequestFile{
			FieldName:     fieldName,
			FileName:      fileName,
			ContentBase64: contentBase64,
		}
		if contentType != "" {
			file.ContentType = &contentType
		}
		files = append(files, file)
	}
	return files, nil
}

// getDiscoverApplicationConfig builds the config for application fingerprinting discovery.
func getDiscoverApplicationConfig(targets []string, resource string, templatePaths []string, timeout int, threads int, proxy string, verboseLogs bool, globalRateLimit int, globalTimeout int, userAgent common.UserAgentPreset) (*discover.DiscoverApplicationConfig, error) {
	resourceEnum, err := getDiscoverApplicationResourceConfigTypeFromString(resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resource)
	}

	config := &discover.DiscoverApplicationConfig{
		Targets:         targets,
		ResourceType:    &resourceEnum,
		TemplatePaths:   templatePaths,
		Timeout:         timeout,
		Threads:         threads,
		Proxy:           &proxy,
		VerboseLogs:     verboseLogs,
		GlobalRateLimit: max(0, globalRateLimit),
		GlobalTimeout:   max(0, globalTimeout),
		UserAgent:       userAgent,
	}
	return config, nil
}

// getDiscoverPageConfig builds the config for page capture and analysis.
func getDiscoverPageConfig(target string, sensitiveContentDetection bool, sensitiveContentFingerprintsPath string, responseCodes string, maxRedirects int, verifyTLS bool, timeout int, ignoreCrossDomainRedirects bool, takeScreenshot bool, userAgent common.UserAgentPreset, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverPageConfig {
	config := discover.DiscoverPageConfig{
		Target:                     target,
		ResponseCodes:              responseCodes,
		SensitiveContentDetection:  sensitiveContentDetection,
		MaxRedirects:               maxRedirects,
		VerifyTls:                  verifyTLS,
		Timeout:                    max(timeout, 0),
		IgnoreCrossDomainRedirects: ignoreCrossDomainRedirects,
		Screenshot:                 takeScreenshot,
		UserAgent:                  userAgent,
		RequestMethod:              requestMethod,
		HeadlessConfig:             headlessConfig,
		BrowserbaseConfig:          browserbaseConfig,
	}
	if sensitiveContentFingerprintsPath != "" {
		config.SensitiveContentFingerprintsPath = &sensitiveContentFingerprintsPath
	}
	return config
}

// getDiscoverProbeConfig builds the config for probe discovery.
func getDiscoverProbeConfig(targets []string, protocol string, maxRedirects int, verifyTLS bool, timeout int, sleep int, jitter int, ignoreCrossDomainRedirects bool, userAgent common.UserAgentPreset, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) *discover.DiscoverProbeConfig {
	config := &discover.DiscoverProbeConfig{
		Targets:                    targets,
		MaxRedirects:               maxRedirects,
		VerifyTls:                  verifyTLS,
		Timeout:                    max(timeout, 0),
		Sleep:                      max(sleep, 0),
		Jitter:                     max(jitter, 0),
		IgnoreCrossDomainRedirects: ignoreCrossDomainRedirects,
		UserAgent:                  userAgent,
		RequestMethod:              requestMethod,
		HeadlessConfig:             headlessConfig,
		BrowserbaseConfig:          browserbaseConfig,
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
func getDiscoverRouteConfig(target string, ignoreCrossDomain bool, collectStaticAssets bool, spiderDepth int, maxRedirects int, verifyTLS bool, timeout int, sleep int, jitter int, threads int, userAgent common.UserAgentPreset, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig, bundleURLs []string, fetchSourceMaps bool, maxBundles int) discover.DiscoverRouteConfig {
	config := discover.DiscoverRouteConfig{
		Target:              target,
		CollectStaticAssets: collectStaticAssets,
		IgnoreCrossDomain:   ignoreCrossDomain,
		SpiderDepth:         spiderDepth,
		MaxRedirects:        maxRedirects,
		VerifyTls:           verifyTLS,
		Timeout:             max(timeout, 0),
		Sleep:               max(sleep, 0),
		Jitter:              max(jitter, 0),
		Threads:             max(threads, 0),
		UserAgent:           userAgent,
		RequestMethod:       requestMethod,
		HeadlessConfig:      headlessConfig,
		BrowserbaseConfig:   browserbaseConfig,
		FetchSourceMaps:     fetchSourceMaps,
		MaxBundles:          maxBundles,
	}

	if len(bundleURLs) > 0 {
		config.BundleUrls = bundleURLs
	}

	return config
}

// getDiscoverSaasConfig builds the config for SaaS active discovery.
func getDiscoverSaasConfig(orgs []string, saasCompanies []string, ssoCompanies []string, maxRedirects int, verifyTLS bool, timeout int, sleep int, jitter int, threads int, userAgent common.UserAgentPreset, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, browserbaseConfig *common.BrowserbaseRequestConfig) discover.DiscoverSaasConfig {
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
		UserAgent:         userAgent,
		RequestMethod:     requestMethod,
		HeadlessConfig:    headlessConfig,
		BrowserbaseConfig: browserbaseConfig,
	}
	return config
}

// getDiscoverDirectoryConfig builds the config for directory discovery.
func getDiscoverDirectoryConfig(targets []string, paths []string, wordlistType string, wordlistSize string, httpMethods []common.HttpMethod, responseCodes string, ignoreBaseContentMatch bool, omitStandardResponses bool, verifyTLS bool, threshold float64, timeout int, ignoreCrossDomainRedirects bool, maxRedirectsBaselineRequest int, threads int, maxRuntime int, retries int, sleep int, jitter int, userAgent common.UserAgentPreset) discover.DiscoverDirectoryConfig {
	config := discover.DiscoverDirectoryConfig{
		Targets:                     targets,
		Paths:                       paths,
		HttpMethods:                 httpMethods,
		ResponseCodes:               responseCodes,
		IgnoreBaseContentMatch:      ignoreBaseContentMatch,
		OmitStandardResponses:       omitStandardResponses,
		VerifyTls:                   verifyTLS,
		Threshold:                   threshold,
		Timeout:                     timeout,
		IgnoreCrossDomainRedirects:  ignoreCrossDomainRedirects,
		MaxRedirectsBaselineRequest: maxRedirectsBaselineRequest,
		Threads:                     threads,
		MaxRuntime:                  maxRuntime,
		Retries:                     retries,
		Sleep:                       sleep,
		Jitter:                      jitter,
		UserAgent:                   userAgent,
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

// getDiscoverWordlistConfig builds the config for wordlist generation.
func getDiscoverWordlistConfig(target string, minWordLength int, spiderDepth int, includeMetadata bool, includeComments bool, includeAltText bool, ignoreCrossDomain bool, verifyTLS bool, timeout int, threads int, sleep int, jitter int, userAgent common.UserAgentPreset) discover.DiscoverWordlistConfig {
	return discover.DiscoverWordlistConfig{
		Target:            target,
		MinWordLength:     max(minWordLength, 1),
		SpiderDepth:       max(spiderDepth, 1),
		IncludeMetadata:   includeMetadata,
		IncludeComments:   includeComments,
		IncludeAltText:    includeAltText,
		IgnoreCrossDomain: ignoreCrossDomain,
		VerifyTls:         verifyTLS,
		Timeout:           max(timeout, 0),
		Threads:           max(threads, 0),
		Sleep:             max(sleep, 0),
		Jitter:            max(jitter, 0),
		UserAgent:         userAgent,
	}
}
