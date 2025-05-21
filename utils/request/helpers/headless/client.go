package headless

import (
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// External
	rod "github.com/go-rod/rod"
	cdp "github.com/go-rod/rod/lib/cdp"
)

type Requester struct {
	Browser                    *rod.Browser
	PathToBrowser              *string
	TimeoutSeconds             int
	MinDOMStabalizeTimeSeconds int
}

func NewRequester(timeout int, config *common.HeadlessRequestConfig) *Requester {
	return &Requester{
		Browser:                    nil,
		PathToBrowser:              config.PathToBrowserShell,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: config.MinDomStabalizeTime,
	}
}

func NewRequesterWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *Requester {
	return &Requester{
		Browser:                    rod.New().Client(client).MustConnect(),
		PathToBrowser:              nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}
