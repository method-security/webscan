package pagecapture

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	pagecapturefern "github.com/Method-Security/webscan/generated/go/pagecapture"
	pagecapture "github.com/Method-Security/webscan/internal/pagecapture/helpers"
	"github.com/Method-Security/webscan/internal/pagecapture/helpers/browserbase"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func PerformHTMLPageCapture(ctx context.Context, target string, captureMethod common.CaptureMethod, baseURLsOnly bool, captureStaticAssets bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option) pagecapturefern.PageCaptureHtmlReport {
	log := svc1log.FromContext(ctx)

	switch captureMethod {
	case common.CaptureMethodRequest:
		log.Info("Initiating page capture with request method", svc1log.SafeParam("target", target))
		capturer := pagecapture.NewRequestPageCapturer(insecure, timeout)
		report, err := capturer.Capture(ctx, target, &pagecapture.Options{})
		if err != nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{err.Error()},
			}
		}
		_ = capturer.Close(ctx)
		return *report

	case common.CaptureMethodBrowser:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", target))
		capturer := pagecapture.NewBrowserPageCapturer(browserPath, timeout, minDOMStabalizeTime)
		report, err := capturer.Capture(ctx, target, &pagecapture.Options{})
		if err != nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{err.Error()},
			}
		}
		_ = capturer.Close(ctx)
		return *report

	case common.CaptureMethodBrowserbase:
		log.Info("Initiating page capture with browserbase method", svc1log.SafeParam("target", target))
		if browserBaseToken == nil || browserBaseProject == nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{"browserbase token and project are required"},
			}
		}
		client := browserbase.NewBrowserbaseClient(*browserBaseToken, *browserBaseProject, browserbase.NewBrowserbaseOptions(ctx, *browserBaseOptions...))
		capturer := pagecapture.NewBrowserbasePageCapturer(ctx, timeout, minDOMStabalizeTime, client)
		if capturer == nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{"failed to create browserbase capturer"},
			}
		}
		report, err := capturer.Capture(ctx, target, &pagecapture.Options{})
		if err != nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{err.Error()},
			}
		}
		err = capturer.Close(ctx)
		if err != nil {
			log.Debug("Failed to close browserbase capturer", svc1log.SafeParam("error", err.Error()))
		}
		return *report

	default:
		return pagecapturefern.PageCaptureHtmlReport{
			Errors: []string{"unsupported capture method"},
		}
	}
}
