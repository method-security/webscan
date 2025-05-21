package utils

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

// RequestMethodFlagData holds all the configuration related to request methods
type RequestMethodFlagData struct {
	RequestMethodEnum  common.RequestMethod
	HeadlessConfig     *common.HeadlessRequestConfig
	BrowserbaseConfig  *common.BrowserbaseRequestConfig
	BrowserbaseSecrets *common.BrowserbaseRequestSecrets
}

// GetRequestMethodFlags extracts and validates all request method related configuration from a cobra command
func GetRequestMethodFlags(cmd *cobra.Command) (*RequestMethodFlagData, error) {
	// Get Request Method flag
	requestMethod, err := cmd.Flags().GetString("request-method")
	if err != nil {
		return nil, fmt.Errorf("failed to get request-method flag: %w", err)
	}
	requestMethodEnum, err := common.NewRequestMethodFromString(strings.ToUpper(requestMethod))
	if err != nil {
		return nil, fmt.Errorf("invalid request method: %w", err)
	}

	flags := &RequestMethodFlagData{
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
