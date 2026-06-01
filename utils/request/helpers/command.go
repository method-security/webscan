package request

import (
	// Standard
	"fmt"
	"os"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// External
	cobra "github.com/spf13/cobra"
)

// MethodFlagData holds all the configuration related to request methods
type MethodFlagData struct {
	RequestMethodEnum  common.RequestMethod
	HeadlessConfig     *common.HeadlessRequestConfig
	BrowserbaseConfig  *common.BrowserbaseRequestConfig
	BrowserbaseSecrets *common.BrowserbaseRequestSecrets
}

// GetUserAgentFlag extracts and validates the user-agent flag from a cobra command.
// Returns UserAgentPresetRandom if the flag is not registered on this command.
func GetUserAgentFlag(cmd *cobra.Command) (common.UserAgentPreset, error) {
	flag := cmd.Flags().Lookup("user-agent")
	if flag == nil {
		return common.UserAgentPresetRandom, nil
	}
	val, err := cmd.Flags().GetString("user-agent")
	if err != nil {
		return "", fmt.Errorf("failed to get user-agent flag: %w", err)
	}
	preset, err := common.NewUserAgentPresetFromString(strings.ToUpper(val))
	if err != nil {
		return "", fmt.Errorf("invalid user-agent preset: %w", err)
	}
	return preset, nil
}

// ValidateUserAgentWithRequestMethod returns an error if the user explicitly set
// --user-agent to a non-default value while using a request method that ignores it
// (headless or browserbase). If --user-agent was left at the default (RANDOM),
// no error is returned since the user didn't explicitly request a specific UA.
func ValidateUserAgentWithRequestMethod(userAgent common.UserAgentPreset, requestMethod common.RequestMethod) error {
	if userAgent == "" || userAgent == common.UserAgentPresetRandom {
		return nil
	}
	if requestMethod == common.RequestMethodHeadless || requestMethod == common.RequestMethodBrowserbase {
		return fmt.Errorf("--user-agent flag is not supported with %s request method", requestMethod)
	}
	return nil
}

// GetRequestMethodFlags extracts and validates all request method related configuration from a cobra command
func GetRequestMethodFlags(cmd *cobra.Command) (*MethodFlagData, error) {
	// Get Request Method flag
	requestMethod, err := cmd.Flags().GetString("request-method")
	if err != nil {
		return nil, fmt.Errorf("failed to get request-method flag: %w", err)
	}
	requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
	if err != nil {
		return nil, fmt.Errorf("invalid request method: %w", err)
	}

	flags := &MethodFlagData{
		RequestMethodEnum: requestMethodEnum,
	}

	// Handle headless browser or browserbase flags
	if requestMethodEnum == common.RequestMethodHeadless || requestMethodEnum == common.RequestMethodBrowserbase {
		bPath, err := cmd.Flags().GetString("headless-path")
		if err != nil {
			return nil, fmt.Errorf("failed to get headless-path flag: %w", err)
		}
		flags.HeadlessConfig = &common.HeadlessRequestConfig{
			PathToBrowserShell: &bPath,
		}
		domTime, err := cmd.Flags().GetInt("min-dom-stabalize-time")
		if err != nil {
			return nil, fmt.Errorf("failed to get min-dom-stabalize-time flag: %w", err)
		}
		flags.HeadlessConfig.MinDomStabalizeTime = domTime
	}

	// Handle browserbase-specific flags
	if requestMethodEnum == common.RequestMethodBrowserbase {
		// Config flags
		proxy, err := cmd.Flags().GetBool("browserbase-proxy")
		if err != nil {
			return nil, fmt.Errorf("failed to get browserbase-proxy flag: %w", err)
		}
		countries, err := cmd.Flags().GetStringSlice("browserbase-countries")
		if err != nil {
			return nil, fmt.Errorf("failed to get browserbase-countries flag: %w", err)
		}
		flags.BrowserbaseConfig = &common.BrowserbaseRequestConfig{
			Proxy:     &proxy,
			Countries: countries,
		}

		// Get browserbase secrets from environment variables
		tokenStr := cmd.Flag("browserbase-token").Value.String()
		if tokenStr == "" {
			tokenStr = os.Getenv("BROWSERBASE_TOKEN")
		}
		projectStr := cmd.Flag("browserbase-project").Value.String()
		if projectStr == "" {
			projectStr = os.Getenv("BROWSERBASE_PROJECT")
		}

		flags.BrowserbaseSecrets = &common.BrowserbaseRequestSecrets{
			Project: projectStr,
			Token:   tokenStr,
		}
	}

	return flags, nil
}
