package main

import (
	"os"

	"github.com/Method-Security/webscan/cmd"
)

var version = "none"

func main() {
	webscan := cmd.NewWebScan(version)
	webscan.InitRootCommand()
	webscan.InitDiscoverCommand()
	webscan.InitEnumerateCommand()
	webscan.InitPentestCommand()

	if err := webscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if webscan.OutputSignal.Status != 0 {
		os.Exit(1)
	}

	os.Exit(0)
}
