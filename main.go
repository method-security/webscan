package main

import (
	"flag"
	"os"

	"github.com/Method-Security/webscan/cmd"
)

var version = "none"

func main() {
	flag.Parse()

	webscan := cmd.NewWebScan(version)
	webscan.InitRootCommand()
	webscan.InitAppCommand()
	webscan.InitCaptureCommand()
	webscan.InitGeneralCommand()

	if err := webscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
