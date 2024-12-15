package cmd

import (
	"github.com/Method-Security/webscan/internal/spider"
	"github.com/spf13/cobra"
)

// InitSpiderCommand initializes the spider command for the webscan CLI. This command is used to perform a web spider crawl
// against URL targets, capturing data about webpages and endpoints that exist on the target.
func (a *WebScan) InitSpiderCommand() {
	spiderCmd := &cobra.Command{
		Use:   "spider",
		Short: "Perform a web web spider crawl against URL targets",
		Long:  `Perform a web web spider crawl against URL targets`,
		Run: func(cmd *cobra.Command, args []string) {
			defer a.OutputSignal.PanicHandler(cmd.Context())

			// Target flag
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate report
			report := spider.PerformWebSpider(cmd.Context(), targets)
			if len(report.Errors) > 0 {
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	spiderCmd.Flags().StringSlice("targets", []string{}, "Url targets to perform web spidering, comma delimited list")

	_ = spiderCmd.MarkFlagRequired("targets")

	a.RootCmd.AddCommand(spiderCmd)
}
