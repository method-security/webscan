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
	ownsBrowser                bool
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

// NewRequesterwithBrowser creates a new Requester with the given timeout and headless configuration.
func NewRequesterwithBrowser(timeout int, config *common.HeadlessRequestConfig) *Requester {
	var browser *rod.Browser
	if config.Browser != nil {
		browser, _ = config.Browser.(*rod.Browser)
	}
	return &Requester{
		Browser:                    browser,
		PathToBrowser:              config.PathToBrowserShell,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: config.MinDomStabalizeTime,
	}
}

// NewRequesterWithClient creates a new Requester using an existing rod cdp.Client.
func NewRequesterWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *Requester {
	browser := rod.New().Client(client)
	_ = browser.Connect()

	return &Requester{
		Browser:                    browser,
		PathToBrowser:              nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}
