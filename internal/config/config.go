// Package config contains common configuration values that are used by the various commands and subcommands in the CLI.
package config

type RootFlags struct {
	Quiet   bool
	Verbose bool
}

type RequestFlags struct {
	RequestMethod       *string
	HeadlessPath        *string
	MinDomStabalizeTime *int
	BrowserbaseToken    *string
	BrowserbaseProject  *string
	Proxy               *bool
	Countries           *[]string
}
