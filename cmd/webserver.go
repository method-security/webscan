package cmd

import (
	"fmt"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	webserver "github.com/Method-Security/webscan/internal/webserver"
	"github.com/spf13/cobra"
)

// InitWebServerCommand initializes the probe command for the webscan CLI. This command is used to perform a web probe against
// targets to identify the existence of web servers.
func (a *WebScan) InitWebServerCommand() {
	webServerCmd := &cobra.Command{
		Use:   "webserver",
		Short: "Perform webserver analysis",
		Long:  `Perform webserver analysis`,
	}

	probeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Perform a web probe against targets to identify existence of web servers",
		Long:  `Perform a web probe against targets to identify existence of web servers`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			targets, err := cmd.Flags().GetString("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := webserver.PerformWebServerProbe(cmd.Context(), targets, time.Duration(timeout)*time.Second)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report

		},
	}

	probeCmd.Flags().String("targets", "", "Address targets to perform webserver probing agains, comma delimited list")
	probeCmd.Flags().Int("timeout", 30, "Timeout limit in seconds")

	webServerCmd.AddCommand(probeCmd)

	headerCmd := &cobra.Command{
		Use:   "header",
		Short: "Perform actions on a webservers headers",
		Long:  `Perform actions on a webservers headers`,
	}

	headerGrabCmd := &cobra.Command{
		Use:   "grab",
		Short: "Grab the response headers given a URL of a webserver",
		Long:  `Grab the response headers given a URL of a webserver`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := webserver.PerformHeaderGrab(cmd.Context(), targets, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report

		},
	}

	headerGrabCmd.Flags().StringSlice("targets", []string{}, "Url of target")
	headerGrabCmd.Flags().Int("timeout", 5, "Timeout limit in seconds")
	headerCmd.AddCommand(headerGrabCmd)
	webServerCmd.AddCommand(headerCmd)

	enumerationCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate a specific type of web server",
		Long:  `Enumerate a specific type of web server`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			updatedTargets := addSchemesToTargets(targets)

			// ServerType
			server, err := cmd.Flags().GetString("server")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			serverEnum, err := webscan.NewServerTypeFromString(strings.ToUpper(server))
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("invalid server type '%s': must be either 'APACHE' or 'NGINX'", server))
				return
			}

			// Modules
			modules, err := cmd.Flags().GetStringSlice("modules")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			moduleEnums, err := validateModuleSelection(modules)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Run Configs
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config, err := newLoadWebserverTypeConfig(updatedTargets, serverEnum, moduleEnums, webscan.ProbeTypeEnumerate, timeout, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			engine := webserver.NewEngine(config)
			report, err := engine.Launch(cmd.Context())
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}

	enumerationCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	enumerationCmd.Flags().String("server", "", "Server type to target (nginx, apache)")
	enumerationCmd.Flags().StringSlice("modules", []string{}, "Server specfic modules to run (default all)")
	enumerationCmd.Flags().Int("timeout", 5000, "Timeout limit in milliseconds")
	enumerationCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = enumerationCmd.MarkFlagRequired("targets")
	_ = enumerationCmd.MarkFlagRequired("server")

	webServerCmd.AddCommand(enumerationCmd)

	a.RootCmd.AddCommand(webServerCmd)

	validationCmd := &cobra.Command{
		Use:   "validate",
		Short: "Preform validation against a specific type of web server",
		Long:  `Preform validation against a specific type of web server`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			updatedTargets := addSchemesToTargets(targets)

			// ServerType
			server, err := cmd.Flags().GetString("server")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			serverEnum, err := webscan.NewServerTypeFromString(strings.ToUpper(server))
			if err != nil {
				a.OutputSignal.AddError(fmt.Errorf("invalid server type '%s': must be either 'APACHE' or 'NGINX'", server))
				return
			}

			// Modules
			modules, err := cmd.Flags().GetStringSlice("modules")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			moduleEnums, err := validateModuleSelection(modules)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Run Configs
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			config, err := newLoadWebserverTypeConfig(updatedTargets, serverEnum, moduleEnums, webscan.ProbeTypeValidate, timeout, successfulOnly)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			engine := webserver.NewEngine(config)
			report, err := engine.Launch(cmd.Context())
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}

	validationCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	validationCmd.Flags().String("server", "", "Server type to target (nginx, apache)")
	validationCmd.Flags().StringSlice("modules", []string{}, "Server specfic modules to run (default all)")
	validationCmd.Flags().Int("timeout", 5000, "Timeout limit in milliseconds")
	validationCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")

	_ = validationCmd.MarkFlagRequired("targets")
	_ = validationCmd.MarkFlagRequired("server")

	webServerCmd.AddCommand(validationCmd)

	a.RootCmd.AddCommand(webServerCmd)
}

func newLoadWebserverTypeConfig(targets []string, serverEnum webscan.ServerType, moduleEnums []webscan.ModuleName, probeEnum webscan.ProbeType, timeout int, successfulOnly bool) (*webscan.WebServerTypeConfig, error) {
	config := &webscan.WebServerTypeConfig{
		Targets:        targets,
		Probe:          probeEnum,
		Server:         serverEnum,
		Modules:        moduleEnums,
		Timeout:        timeout,
		SuccessfulOnly: successfulOnly,
	}
	if config.Timeout < 1 {
		config.Timeout = 0
	}
	return config, nil
}

func addSchemesToTargets(targets []string) []string {
	var updatedTargets []string
	for _, target := range targets {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			updatedTargets = append(updatedTargets, target)
		} else {
			updatedTargets = append(updatedTargets, "http://"+target)
			updatedTargets = append(updatedTargets, "https://"+target)
		}
	}
	return updatedTargets
}

func validateModuleSelection(modules []string) ([]webscan.ModuleName, error) {
	moduleEnums := []webscan.ModuleName{}
	if len(modules) == 0 {
		return nil, nil
	}
	for _, module := range modules {
		moduleEnum, err := webscan.NewModuleNameFromString(strings.ToUpper(module))
		if err != nil {
			return nil, err
		}
		moduleEnums = append(moduleEnums, moduleEnum)
	}

	return moduleEnums, nil
}
