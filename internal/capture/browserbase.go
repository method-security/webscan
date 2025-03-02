package capture

import (
	"context"

	webscan "github.com/Method-Security/webscan/generated/go/pagecapture"
	"github.com/Method-Security/webscan/internal/browserbase"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type BrowserbasePageCapturer struct {
	Client   *browserbase.Client
	Capturer *BrowserPageCapturer
}

func NewBrowserbasePageCapturer(
	ctx context.Context,
	timeout int,
	minDOMStabalizeTime int,
	browserbaseClient *browserbase.Client,
) *BrowserbasePageCapturer {
	session, err := browserbaseClient.CreateSession(ctx)
	if err != nil {
		svc1log.FromContext(ctx).Error("Failed to create session. Aborting.")
		return nil
	}

	websocket := NewWebSocket(ctx, browserbaseClient.ConnectionString(*session))
	client := cdp.New().Start(websocket)
	return &BrowserbasePageCapturer{
		Capturer: NewBrowserPageCapturerWithClient(client, timeout, minDOMStabalizeTime),
		Client:   browserbaseClient,
	}
}

func (b *BrowserbasePageCapturer) Capture(ctx context.Context, url string, options *Options) (*webscan.PageCaptureReport, error) {
	return b.Capturer.Capture(ctx, url, options)
}

func (b *BrowserbasePageCapturer) Close(ctx context.Context) error {
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
