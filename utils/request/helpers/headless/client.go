package headless

import (
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// External
	rod "github.com/go-rod/rod"
	cdp "github.com/go-rod/rod/lib/cdp"
)

// Requester manages a headless browser instance and configuration for making requests.
type Requester struct {
	Browser                    *rod.Browser
	PathToBrowser              *string
	TimeoutSeconds             int
	MinDOMStabalizeTimeSeconds int
}

// NewRequester creates a new Requester with the given timeout and headless configuration.
func NewRequester(timeout int, config *common.HeadlessRequestConfig) *Requester {
	return &Requester{
		Browser:                    nil,
		PathToBrowser:              config.PathToBrowserShell,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: config.MinDomStabalizeTime,
	}
}

// NewRequesterWithClient creates a new Requester using an existing rod cdp.Client.
func NewRequesterWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *Requester {
	return &Requester{
		Browser:                    rod.New().Client(client).MustConnect(),
		PathToBrowser:              nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}
