package cmd

import (
	"github.com/Method-Security/webscan/internal/url/fingerprint"
	"github.com/spf13/cobra"
)

// InitURLCommand initializes the URL command for the webscan CLI. This command is used to perform a URL scan against a URL target,
// capturing data TLS and HTTP methods that exist on the URL.
func (a *WebScan) InitURLCommand() {
	urlCmd := &cobra.Command{
		Use:   "url",
		Short: "Perform a URL scan against a URL target",
		Long:  `Perform a URL scan against a URL target`,
	}

	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Given a URL target, grab the HTTP headers to enable further analysis on specific headers and their values.",
		Long:  `Given a URL target, grab the HTTP headers to enable further analysis on specific headers and their values.`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := fingerprint.PerformFingerprint(cmd.Context(), target)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	fingerprintCmd.Flags().String("target", "", "Url target to perform fingerprint")

	urlCmd.AddCommand(fingerprintCmd)
	a.RootCmd.AddCommand(urlCmd)
}
