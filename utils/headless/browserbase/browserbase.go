package browserbase

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils/headless"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type PageCapturer struct {
	Client   Client
	Capturer *headless.BrowserPageCapturer
}

func NewBrowserbasePageCapturer(
	ctx context.Context,
	timeout int,
	minDOMStabalizeTime int,
	browserbaseClient Client,
) *PageCapturer {
	session, err := browserbaseClient.CreateSession(ctx)
	if err != nil {
		svc1log.FromContext(ctx).Error("Failed to create session. Aborting.")
		return nil
	}

	websocket := headless.NewWebSocket(ctx, browserbaseClient.ConnectionString(*session))
	client := cdp.New().Start(websocket)
	return &PageCapturer{
		Capturer: headless.NewBrowserPageCapturerWithClient(client, timeout, minDOMStabalizeTime),
		Client:   browserbaseClient,
	}
}

func (b *PageCapturer) Capture(ctx context.Context, url string, options *headless.Options) (*common.RequestInfo, error) {
	return b.Capturer.Capture(ctx, url, options)
}

func (b *PageCapturer) Close(ctx context.Context) error {
	var err error = nil
	sessionErr := b.Client.CloseAllSessions(ctx)
	if sessionErr != nil {
		svc1log.FromContext(ctx).Error("Failed to close all sessions")
		err = sessionErr
	}
	captureErr := b.Capturer.Close(ctx)
	if captureErr != nil {
		svc1log.FromContext(ctx).Error("Failed to close browser capturer")
		err = captureErr
	}
	return err
}
