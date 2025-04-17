package browserbase

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/palantir/pkg/safejson"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func NewBrowserbaseClient(apiKey string, projectID string, options *Options) *Client {
	return &Client{
		APIKey:        apiKey,
		URL:           "https://www.browserbase.com",
		ConnectionURL: "wss://connect.browserbase.com",
		ProjectID:     projectID,
		Sessions:      []*Session{},
		Options:       options,
	}
}

func (b *Client) ConnectionString(session Session) string {
	return fmt.Sprintf("%s?apiKey=%s&sessionId=%s", b.ConnectionURL, b.APIKey, session.ID)
}

func (b *Client) CreateSession(ctx context.Context) (*Session, error) {
	log := svc1log.FromContext(ctx)
	if b.Options == nil {
		log.Debug("No options provided, creating a basic session")
		return b.createBasicSession(ctx)
	} else if len(b.Options.Countries) > 0 && b.Options.Proxy {
		log.Debug("Creating a geo proxy session")
		return b.createGeoProxySession(ctx, b.Options.Countries)
	} else if b.Options.Proxy {
		log.Debug("Creating a proxy session")
		return b.createProxySession(ctx)
	} else {
		log.Debug("Creating a basic session")
		return b.createBasicSession(ctx)
	}
}

func (b *Client) createBasicSession(ctx context.Context) (*Session, error) {
	request := b.createSessionRequest()
	return b.createSession(ctx, &request)
}

func (b *Client) createProxySession(ctx context.Context) (*Session, error) {
	request := b.createSessionRequest()
	request.Proxies = []Proxy{{Type: "browserbase"}}
	return b.createSession(ctx, &request)
}

func (b *Client) createGeoProxySession(ctx context.Context, countryCodes []string) (*Session, error) {
	request := b.createSessionRequest()
	request.Proxies = []Proxy{}
	for _, countryCode := range countryCodes {
		request.Proxies = append(request.Proxies, Proxy{
			Type: "browserbase",
			Geolocation: &Geolocation{
				Country: countryCode,
			},
		})
	}
	return b.createSession(ctx, &request)
}

func (b *Client) CloseSession(ctx context.Context, sessionID string) error {
	log := svc1log.FromContext(ctx)
	if sessionID == "" {
		log.Error("Session ID is empty")
		return fmt.Errorf("Session ID is empty")
	}

	body := CloseSessionRequest{
		ProjectID: b.ProjectID,
		Status:    "REQUEST_RELEASE",
	}
	payloadBytes, err := safejson.Marshal(body)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to marshal payload: %s", err.Error()))
		return err
	}

	request, _ := http.NewRequest("POST", b.URL+"/v1/sessions/"+sessionID, bytes.NewBuffer(payloadBytes))
	request.Header.Add("X-BB-API-Key", b.APIKey)
	request.Header.Add("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Error(fmt.Sprintf("Session request failed: %s", err.Error()))
		return err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			log.Error(fmt.Sprintf("Failed to close response body: %s", cerr.Error()))
			// If err is nil, set it to cerr so that the error is not lost
			if err == nil {
				err = cerr
			}
		}
	}()

	for i, session := range b.Sessions {
		if session.ID == sessionID {
			b.Sessions = append(b.Sessions[:i], b.Sessions[i+1:]...)
			break
		}
	}

	return nil
}

func (b *Client) CloseAllSessions(ctx context.Context) error {
	log := svc1log.FromContext(ctx)
	sessionIDs := make([]string, 0, len(b.Sessions))

	for _, session := range b.Sessions {
		sessionIDs = append(sessionIDs, session.ID)
	}

	var errors []error
	for _, sessionID := range sessionIDs {
		err := b.CloseSession(ctx, sessionID)
		if err != nil {
			log.Error(fmt.Sprintf("Failed to close session: %s", err.Error()))
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("failed to close all sessions: %v", errors)
	}
	return nil
}

func (b *Client) createSessionRequest() CreateSessionRequest {
	return CreateSessionRequest{
		ProjectID: b.ProjectID,
		BrowserSettings: BrowserSettings{
			LogSession:    true,
			RecordSession: true,
			SolveCaptchas: true,
			BlockAds:      true,
		},
	}
}

func (b *Client) createSession(ctx context.Context, createSessionRequest *CreateSessionRequest) (*Session, error) {
	log := svc1log.FromContext(ctx)
	if createSessionRequest == nil {
		log.Error("CreateSessionRequest is nil")
		return nil, fmt.Errorf("CreateSessionRequest is nil")
	}

	payloadBytes, err := safejson.Marshal(createSessionRequest)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to marshal payload: %s", err.Error()))
		return nil, err
	}

	log.Debug(fmt.Sprintf("Creating session with payload: %s", string(payloadBytes)))

	request, _ := http.NewRequest("POST", b.URL+"/v1/sessions", bytes.NewBuffer(payloadBytes))
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-BB-API-Key", b.APIKey)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Error(fmt.Sprintf("Session request failed: %s", err.Error()))
		return nil, err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			log.Error(fmt.Sprintf("Failed to close response body: %s", cerr.Error()))
			if err == nil {
				err = cerr
			}
		}
	}()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to read response body: %s", err.Error()))
		return nil, err
	}

	log.Debug(fmt.Sprintf("Response body: %s", string(body)))

	session := Session{}
	err = safejson.Unmarshal(body, &session)
	if err != nil {
		log.Error(fmt.Sprintf("Failed to unmarshal response body: %s", err.Error()))
		return nil, err
	}

	b.Sessions = append(b.Sessions, &session)
	return &session, nil
}
