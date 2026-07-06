package headless

import (
	// Standard
	"fmt"
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
	HttpProxy                  string
	SocksProxy                 string
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
func NewRequesterWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) (*Requester, error) {
	browser := rod.New().Client(client)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("browser connection failed: %v", err)
	}

	return &Requester{
		Browser:                    browser,
		PathToBrowser:              nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}, nil
}

// SetProxyConfig stores launch-scoped proxy configuration for browser instances
// created by this requester. HTTP takes precedence when both proxies are set.
func (b *Requester) SetProxyConfig(httpProxy, socksProxy string) {
	b.HttpProxy = httpProxy
	b.SocksProxy = socksProxy
}

// SetProxyConfigFromRequest stores proxy configuration from a request config.
func (b *Requester) SetProxyConfigFromRequest(config common.SendHttpRequestConfig) {
	var httpProxy string
	if config.HttpProxy != nil {
		httpProxy = *config.HttpProxy
	}
	var socksProxy string
	if config.SocksProxy != nil {
		socksProxy = *config.SocksProxy
	}
	b.SetProxyConfig(httpProxy, socksProxy)
}

func (b *Requester) proxyServer() string {
	if b.HttpProxy != "" {
		return b.HttpProxy
	}
	return b.SocksProxy
}
