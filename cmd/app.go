package cmd

import (
	"errors"

	"github.com/Method-Security/webscan/internal/graphql"
	"github.com/Method-Security/webscan/internal/grpc"
	"github.com/Method-Security/webscan/internal/k8s"
	"github.com/Method-Security/webscan/internal/swagger"
	"github.com/Method-Security/webscan/internal/vuln"
	"github.com/spf13/cobra"
)

// InitAppCommand initializes the app command for the webscan CLI.
func (a *WebScan) InitAppCommand() {
	a.AppCmd = &cobra.Command{
		Use:   "app",
		Short: "Perform various application scans",
		Long:  `Perform various application scans such as fingerprinting and enumeration`,
	}

	a.RootCmd.AddCommand(a.AppCmd)
	a.initFingerprintCommand()
	a.initEnumerateCommand()
}

func (a *WebScan) initFingerprintCommand() {
	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Perform a fingerprint scan against a target",
		Long: `Perform a fingerprint scan against a target using specified types.
		
The fingerprint command identifies the type of web application running on the target URL. 
It uses custom templates to match URLs hosting different types of web applications or cloud services
such as Swagger, gRPC, GraphQL, and cloud buckets.`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if target == "" {
				err = errors.New("target flag is required")
				a.OutputSignal.AddError(err)
				return
			}

			tags, err := cmd.Flags().GetStringSlice("tags")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if len(tags) == 0 {
				tags = []string{"swagger", "graphql", "grpc", "bucket"}
			}
			rawSeverity, err := cmd.Flags().GetStringSlice("severity")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			severity := parseSeverityIntoString(rawSeverity)
			defaultTemplateDirectory, err := cmd.Flags().GetString("defaultTemplateDirectory")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			customTemplateDirectory, err := cmd.Flags().GetString("customTemplateDirectory")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := vuln.PerformVulnScan(cmd.Context(), target, tags, severity, defaultTemplateDirectory, customTemplateDirectory)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}

	fingerprintCmd.Flags().String("target", "", "URL target to perform fingerprinting against")
	fingerprintCmd.Flags().StringSlice("tags", []string{}, "Tags to filter templates by")
	fingerprintCmd.Flags().StringSlice("severity", []string{}, "Severity to filter templates by")
	fingerprintCmd.Flags().String("defaultTemplateDirectory", "", "Directory to load default templates from")
	fingerprintCmd.Flags().String("customTemplateDirectory", "", "Directory to load custom templates from")

	a.AppCmd.AddCommand(fingerprintCmd)
}

func (a *WebScan) initEnumerateCommand() {
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Perform enumeration scans against a target",
		Long: `Perform enumeration scans against a target using specified types.
		
The enumerate command details the routes and endpoints for an API application. 
It extracts information such as available endpoints, HTTP methods, query parameters, and authentication mechanisms.`,
	}

	enumerateCmd.AddCommand(a.initGraphqlEnumerateCommand())
	enumerateCmd.AddCommand(a.initGrpcEnumerateCommand())
	enumerateCmd.AddCommand(a.initK8sEnumerateCommand())
	enumerateCmd.AddCommand(a.initSwaggerEnumerateCommand())

	a.AppCmd.AddCommand(enumerateCmd)
}

func (a *WebScan) initGraphqlEnumerateCommand() *cobra.Command {
	graphqlCmd := &cobra.Command{
		Use:   "graphql",
		Short: "Perform a GraphQL enumeration scan against a target",
		Long: `Perform a GraphQL enumeration scan against a target.
		
This involves querying the GraphQL schema to discover available types, queries, mutations, and subscriptions, 
and extracting details about the fields and their types.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := graphql.PerformGraphQLScan(cmd.Context(), target)
			a.OutputSignal.Content = report
		},
	}

	graphqlCmd.Flags().String("target", "", "URL target to perform GraphQL enumeration against")

	_ = graphqlCmd.MarkFlagRequired("target")

	return graphqlCmd
}

func (a *WebScan) initGrpcEnumerateCommand() *cobra.Command {
	grpcCmd := &cobra.Command{
		Use:   "grpc",
		Short: "Perform a gRPC enumeration scan against a target",
		Long: `Perform a gRPC enumeration scan against a target.
		
This involves connecting to the gRPC server, using reflection to discover available services and methods, 
and extracting details about the methods, including their input and output types.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := grpc.PerformGRPCScan(cmd.Context(), target)
			a.OutputSignal.Content = report
		},
	}

	grpcCmd.Flags().String("target", "", "URL target to perform gRPC enumeration against")

	_ = grpcCmd.MarkFlagRequired("target")

	return grpcCmd
}

func (a *WebScan) initK8sEnumerateCommand() *cobra.Command {
	k8sCmd := &cobra.Command{
		Use:   "k8s",
		Short: "Perform a K8s enumeration scan against a target",
		Long:  `Perform a K8s enumeration scan against a target.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := k8s.PerformK8sScan(cmd.Context(), target, timeout)
			a.OutputSignal.Content = report
		},
	}

	k8sCmd.Flags().Int("timeout", 3000, "Timeout per request (milliseconds)")
	k8sCmd.Flags().String("target", "", "URL target to perform K8s enumeration against")

	_ = k8sCmd.MarkFlagRequired("target")

	return k8sCmd
}

func (a *WebScan) initSwaggerEnumerateCommand() *cobra.Command {
	swaggerCmd := &cobra.Command{
		Use:   "swagger",
		Short: "Perform a Swagger enumeration scan against a target",
		Long: `Perform a Swagger enumeration scan against a target.
		
This involves fetching and parsing the Swagger (OpenAPI) documentation to extract details about the available endpoints, 
HTTP methods, query parameters, and authentication mechanisms.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			noSandbox, err := cmd.Flags().GetBool("no-sandbox")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report := swagger.PerformSwaggerScan(cmd.Context(), target, noSandbox)
			a.OutputSignal.Content = report
		},
	}

	swaggerCmd.Flags().String("target", "", "URL target to perform Swagger enumeration against")
	swaggerCmd.Flags().Bool("no-sandbox", false, "Disable sandbox mode for Swagger scan")

	_ = swaggerCmd.MarkFlagRequired("target")

	return swaggerCmd
}
