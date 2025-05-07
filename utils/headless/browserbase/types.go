package browserbase

type Session struct {
	ID        string `json:"id,omitempty"`
	Status    string `json:"status,omitempty"`
	ContextID string `json:"contextId,omitempty"`
}

type Geolocation struct {
	City    string `json:"city,omitempty"`
	State   string `json:"state,omitempty"`
	Country string `json:"country,omitempty"`
}

type Proxy struct {
	Type        string       `json:"type"`
	Geolocation *Geolocation `json:"geolocation,omitempty"`
}

type BrowserSettings struct {
	BlockAds      bool `json:"blockAds,omitempty"`
	SolveCaptchas bool `json:"solveCaptchas,omitempty"`
	RecordSession bool `json:"recordSession,omitempty"`
	LogSession    bool `json:"logSession,omitempty"`
}

type CreateSessionRequest struct {
	ProjectID       string          `json:"projectId,omitempty"`
	BrowserSettings BrowserSettings `json:"browserSettings,omitempty"`
	Proxies         []Proxy         `json:"proxies,omitempty"`
}

type CloseSessionRequest struct {
	ProjectID string `json:"projectId,omitempty"`
	Status    string `json:"status,omitempty"`
}

type Client struct {
	APIKey        string
	URL           string
	ConnectionURL string
	ProjectID     string
	Sessions      []*Session
	Options       *Options
}
