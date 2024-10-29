package cmd

import (
	"errors"
	"strconv"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/Method-Security/webscan/internal/fuzz"
	"github.com/Method-Security/webscan/utils"
	"github.com/spf13/cobra"
)

func (a *WebScan) InitFuzzCommand() {
	fuzzCmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Perform a web fuzz against a target",
		Long:  `Perform a web fuzz against a target`,
	}

	pathCmd := &cobra.Command{
		Use:   "path",
		Short: "Perform a path-based web fuzz against a target",
		Long:  `Perform a path-based web fuzz against a target`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			paths, err := cmd.Flags().GetStringSlice("paths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			pathlists, err := cmd.Flags().GetStringSlice("pathlists")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			pathsFromFiles, err := utils.GetEntriesFromFiles(pathlists)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allPaths := append(paths, pathsFromFiles...)
			if len(allPaths) == 0 {
				a.OutputSignal.AddError(errors.New("no paths provided"))
				return
			}

			responseCodes, err := cmd.Flags().GetString("responsecodes")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Configs
			ignoreBase, err := cmd.Flags().GetBool("ignore-base-content-match")
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
			retries, err := cmd.Flags().GetInt("retries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Load configuration using LoadPathFuzzConfig
			config, err := LoadPathFuzzConfig(targets, allPaths, responseCodes, ignoreBase, timeout, sleep, retries, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := fuzz.PerformPathFuzz(cmd.Context(), config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Define flags for the path command
	pathCmd.Flags().StringSlice("targets", []string{}, "URL of target")
	pathCmd.Flags().StringSlice("paths", []string{}, "File paths to use in attack")
	pathCmd.Flags().StringSlice("pathlists", []string{}, "File paths containing paths to fuzz")
	pathCmd.Flags().String("responsecodes", "200-299", "Response codes to consider as valid responses")
	pathCmd.Flags().Bool("ignore-base-content-match", true, "Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect")
	pathCmd.Flags().Int("timeout", 3000, "Timeout per request (milliseconds)")
	pathCmd.Flags().Int("sleep", 0, "Sleep time between requests (milliseconds)")
	pathCmd.Flags().Int("retries", 1, "Number of attempts per credential pair")
	pathCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = pathCmd.MarkFlagRequired("targets")

	// Add the path command to fuzz and the root command
	fuzzCmd.AddCommand(pathCmd)
	a.RootCmd.AddCommand(fuzzCmd)
}

// LoadPathFuzzConfig loads the configuration for a path-based fuzzing run.
func LoadPathFuzzConfig(targets, paths []string, responseCodes string, ignoreBaseContent bool, timeout, sleep, retries int, successfulOnly bool) (*webscan.FuzzPathConfig, error) {
	config := &webscan.FuzzPathConfig{
		Targets:           targets,
		Paths:             paths,
		ResponseCodes:     responseCodes,
		IgnoreBaseContent: ignoreBaseContent,
		Timeout:           timeout,
		Sleep:             sleep,
		Retries:           retries,
		SuccessfulOnly:    successfulOnly,
	}

	if !isValidResponseCodeRange(config.ResponseCodes) {
		return nil, errors.New("invalid response code range")
	}
	if config.Timeout < 1 {
		config.Timeout = 0
	}
	if config.Sleep < 0 {
		config.Sleep = 0
	}
	if config.Retries < 0 {
		config.Sleep = 1
	}

	return config, nil
}

// isValidResponseCodeRange checks if the response codes string is in a valid format.
func isValidResponseCodeRange(responseCodes string) bool {
	// Example: "200-299" or "404,403"
	for _, part := range strings.Split(responseCodes, ",") {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return false
			}
		} else {
			if _, err := strconv.Atoi(part); err != nil {
				return false
			}
		}
	}
	return true
}
