package cmd

import (
	"encoding/base64"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/Method-Security/webscan/internal/requests"
	"github.com/spf13/cobra"
)

func (a *WebScan) InitRequestsCommand() {

	requestsCmd := &cobra.Command{
		Use:   "requests",
		Short: "Perform a custom request against a target",
		Long:  `Perform a custom reques against a target using specified parameters`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Required parameters
			baseURL, err := cmd.Flags().GetString("baseUrl")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			method, err := cmd.Flags().GetString("method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Optional parameters
			isEncoded, err := cmd.Flags().GetBool("encodedParams")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			params, err := DecodeAndSetParams(cmd, isEncoded)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			vulnTypes, err := cmd.Flags().GetStringSlice("vulnType")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := requests.PerformRequestScan(baseURL, path, method, *params, vulnTypes)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}

			a.OutputSignal.Content = report
		},
	}

	requestsCmd.PersistentFlags().String("baseUrl", "", "Base URL of the target")
	requestsCmd.PersistentFlags().String("path", "", "Path to append to the base URL")
	requestsCmd.PersistentFlags().String("method", "", "HTTP method to use (GET, POST, etc.)")
	requestsCmd.Flags().String("pathParams", "", "Path parameters as a JSON string (optional)")
	requestsCmd.Flags().String("queryParams", "", "Query parameters as a JSON string (optional)")
	requestsCmd.Flags().String("headerParams", "", "Header parameters as a JSON string (optional)")
	requestsCmd.Flags().String("bodyParams", "", "Body parameters as a JSON string (optional)")
	requestsCmd.Flags().String("formParams", "", "Form parameters as a JSON string (optional)")
	requestsCmd.Flags().String("multipartParams", "", "Multipart form parameters as a JSON string (optional)")
	requestsCmd.Flags().Bool("encodedParams", false, "Request parameters base64 encoded")
	requestsCmd.PersistentFlags().StringSlice("vulnType", []string{}, "Types of vulnerabilities to check (optional)")

	_ = requestsCmd.MarkFlagRequired("baseUrl")
	_ = requestsCmd.MarkFlagRequired("path")
	_ = requestsCmd.MarkFlagRequired("method")

	headerCmd := &cobra.Command{
		Use:   "headers",
		Short: "Perform specfic header injection requests",
		Long:  `Perform specfic header injection requests`,
	}

	serverOverloadCmd := &cobra.Command{
		Use:   "serveroverload",
		Short: "Server overload header requests.",
		Long:  `Define the Header name and value length for server overload requests.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Required Parameters
			baseURL, err := cmd.Flags().GetString("baseUrl")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			method, err := cmd.Flags().GetString("method")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Dynamic header parameters
			headerNames, err := cmd.Flags().GetStringSlice("headerName")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			payloadSize, err := cmd.Flags().GetInt("headerSize")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			vulnTypes, err := cmd.Flags().GetStringSlice("vulnType")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := requests.PerformServerOverloadHeaderRequests(baseURL, path, method, headerNames, payloadSize, vulnTypes)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}

			a.OutputSignal.Content = report

		},
	}
	serverOverloadCmd.Flags().StringSlice("headerName", []string{}, "Specifies Header keys to use in request.")
	serverOverloadCmd.Flags().Int("headerSize", 100, "Specifies the length of header values to include in requests.")

	_ = requestsCmd.MarkFlagRequired("headerName")

	headerCmd.AddCommand(serverOverloadCmd)
	requestsCmd.AddCommand(headerCmd)
	a.RootCmd.AddCommand(requestsCmd)
}

// DecodeAndSetParams decodes flags as base64 if isEncoded is true, and parses JSON for all params.
func DecodeAndSetParams(cmd *cobra.Command, isEncoded bool) (*webscan.RequestParams, error) {
	getFlagValue := func(flagName string) (string, error) {
		flagValue := cmd.Flag(flagName).Value.String()
		if isEncoded {
			decodedBytes, err := base64.StdEncoding.DecodeString(flagValue)
			if err != nil {
				return "", err
			}
			return string(decodedBytes), nil
		}
		return flagValue, nil
	}
	params := webscan.RequestParams{}

	// Decode and parse each parameter
	pathParams, err := getFlagValue("pathParams")
	if err != nil {
		return nil, err
	}
	params.PathParams = pathParams

	queryParams, err := getFlagValue("queryParams")
	if err != nil {
		return nil, err
	}
	params.QueryParams = queryParams

	headerParams, err := getFlagValue("headerParams")
	if err != nil {
		return nil, err
	}
	params.HeaderParams = headerParams

	bodyParams, err := getFlagValue("bodyParams")
	if err != nil {
		return nil, err
	}
	params.BodyParams = bodyParams

	formParams, err := getFlagValue("formParams")
	if err != nil {
		return nil, err
	}
	params.FormParams = formParams

	multipartParams, err := getFlagValue("multipartParams")
	if err != nil {
		return nil, err
	}
	params.MultipartParams = multipartParams

	return &params, nil
}
