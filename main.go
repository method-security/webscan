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
	webscan.InitFingerprintCommand()
	webscan.InitFuzzCommand()
	webscan.InitPagecaptureCommand()
	webscan.InitRequestsCommand()
	webscan.InitRoutecaptureCommand()
	webscan.InitSpiderCommand()
	webscan.InitVulnCommand()
	webscan.InitWebServerCommand()

	if err := webscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
