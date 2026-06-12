package browserbase

import (
	// Standard
	"context"
	"fmt"
	"os"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
	// External
	"github.com/go-rod/rod/lib/cdp"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// Requester is a struct that contains a Client and a Requester
type Requester struct {
	Client    Client
	Requester *headless.Requester
}

// NewBrowserbaseRequester creates a new BrowserbaseRequester
func NewBrowserbaseRequester(
	ctx context.Context,
	browserbaseClient Client,
	timeout int,
	minDOMStabalizeTime int,
) *Requester {
	session, err := browserbaseClient.CreateSession(ctx)
	if err != nil {
		svc1log.FromContext(ctx).Error("Failed to create session. Aborting.")
		return nil
	}

	websocket, err := NewWebSocket(ctx, browserbaseClient.ConnectionString(*session))
	if err != nil {
		svc1log.FromContext(ctx).Error("Failed to create websocket connection", svc1log.SafeParam("error", err.Error()))
		return nil
	}
	client := cdp.New().Start(websocket)
	headlessRequester, err := headless.NewRequesterWithClient(client, timeout, minDOMStabalizeTime)
	if err != nil {
		svc1log.FromContext(ctx).Error("Failed to connect to browserbase CDP session", svc1log.SafeParam("error", err.Error()))
		return nil
	}

	return &Requester{
		Requester: headlessRequester,
		Client:    browserbaseClient,
	}
}

func (b *Requester) SendRequest(ctx context.Context, options common.SendHttpRequestConfig) (common.HttpRequestResponse, error) {
	return b.Requester.SendRequest(ctx, options)
}

func (b *Requester) Close(ctx context.Context) error {
	var err error = nil
	sessionErr := b.Client.CloseAllSessions(ctx)
	if sessionErr != nil {
		svc1log.FromContext(ctx).Error("Failed to close all sessions")
		err = sessionErr
	}
	return err
}

// GetFlagOrEnvironmentVariable retrieves a value from either a command flag or an environment variable.
// It first checks the environment variable, then falls back to the command flag.
// Returns an error if neither source has a value.
func GetFlagOrEnvironmentVariable(cmd *cobra.Command, flagName string, environmentVariableName string) (string, error) {
	var value string
	if envVar, exists := os.LookupEnv(environmentVariableName); exists && envVar != "" {
		value = envVar
	} else if flagValue, err := cmd.Flags().GetString(flagName); err == nil && flagValue != "" {
		value = flagValue
	} else {
		return "", fmt.Errorf("no value provided for %s", flagName)
	}

	return value, nil
}
