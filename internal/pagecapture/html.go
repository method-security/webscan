package pagecapture

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	pagecapturefern "github.com/Method-Security/webscan/generated/go/pagecapture"
	"github.com/Method-Security/webscan/utils"
	"github.com/Method-Security/webscan/utils/headless"
	"github.com/Method-Security/webscan/utils/headless/browserbase"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func PerformHTMLPageCapture(ctx context.Context, target string, captureMethod common.CaptureMethod, baseURLsOnly bool, captureStaticAssets bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option) pagecapturefern.PageCaptureHtmlReport {
	log := svc1log.FromContext(ctx)
	report := pagecapturefern.PageCaptureHtmlReport{}
	switch captureMethod {
	case common.CaptureMethodRequest:
		log.Info("Initiating page capture with request method", svc1log.SafeParam("target", target))
		requestInfo := utils.PerformRequestScan(target, "", common.HttpMethodGet, common.RequestParams{}, timeout, insecure)
		if requestInfo.Errors != nil {
			report.Errors = requestInfo.Errors
		}
		report.Request = &requestInfo
		return report

	case common.CaptureMethodBrowser:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", target))
		capturer := headless.NewBrowserPageCapturer(browserPath, timeout, minDOMStabalizeTime)
		requestInfo, err := capturer.Capture(ctx, target, &headless.Options{})
		if err != nil {
			report.Errors = []string{err.Error()}
		}
		_ = capturer.Close(ctx)
		report.Request = requestInfo
		return report

	case common.CaptureMethodBrowserbase:
		log.Info("Initiating page capture with browserbase method", svc1log.SafeParam("target", target))
		if browserBaseToken == nil || browserBaseProject == nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{"browserbase token and project are required"},
			}
		}
		client := browserbase.NewBrowserbaseClient(*browserBaseToken, *browserBaseProject, browserbase.NewBrowserbaseOptions(ctx, *browserBaseOptions...))
		capturer := browserbase.NewBrowserbasePageCapturer(ctx, timeout, minDOMStabalizeTime, *client)
		if capturer == nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{"failed to create browserbase capturer"},
			}
		}
		requestInfo, err := capturer.Capture(ctx, target, &headless.Options{})
		if err != nil {
			return pagecapturefern.PageCaptureHtmlReport{
				Errors: []string{err.Error()},
			}
		}
		report.Request = requestInfo
		err = capturer.Close(ctx)
		if err != nil {
			log.Debug("Failed to close browserbase capturer", svc1log.SafeParam("error", err.Error()))
		}
		return report

	default:
		return pagecapturefern.PageCaptureHtmlReport{
			Errors: []string{"unsupported capture method"},
		}
	}
}
