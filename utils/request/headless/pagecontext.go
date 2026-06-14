package headless

import (
	// Standard
	"fmt"
	"strings"
	"sync"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"

	// External
	rod "github.com/go-rod/rod"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// consoleCapture accumulates browser console messages emitted during a navigation.
type consoleCapture struct {
	mutex    sync.Mutex
	messages []string
}

func (c *consoleCapture) add(message string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.messages = append(c.messages, message)
}

func (c *consoleCapture) snapshot() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(c.messages) == 0 {
		return nil
	}
	return append([]string(nil), c.messages...)
}

// applyRequestHeaders sets caller-supplied request headers on the page so that
// authenticated headless crawls send the same headers as the standard transport.
// Headers are sourced from the request params; cookies are applied separately.
func applyRequestHeaders(page *rod.Page, config common.SendHttpRequestConfig, log svc1log.Logger) {
	if config.Request == nil || config.Request.Params == nil || len(config.Request.Params.Headers) == 0 {
		return
	}
	flat := make([]string, 0, len(config.Request.Params.Headers)*2)
	for key, values := range config.Request.Params.Headers {
		if strings.EqualFold(key, "Cookie") {
			// Cookies are injected via the cookie jar, not as a raw header.
			continue
		}
		for _, value := range values {
			flat = append(flat, key, value)
		}
	}
	if len(flat) == 0 {
		return
	}
	if _, err := page.SetExtraHeaders(flat); err != nil {
		log.Warn("Failed to set extra headers on headless page", svc1log.SafeParam("error", cleanErrMsg(err)))
	}
}

// parseCookieHeader splits a folded "name=value; name2=value2" Cookie header value
// into its individual cookie pairs. Malformed segments without an '=' are skipped.
func parseCookieHeader(value string) map[string]string {
	cookies := make(map[string]string)
	for _, part := range strings.Split(value, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if name := strings.TrimSpace(kv[0]); name != "" {
			cookies[name] = strings.TrimSpace(kv[1])
		}
	}
	return cookies
}

// mergedCookies combines explicit jar cookies (config.Cookies) with any cookies that
// callers fold into a Cookie request header (e.g. via BuildAuthHeaders, as Swagger's
// headless UI step does). Without this, headless navigations would silently run
// without session cookies whenever the caller only supplied them as a Cookie header,
// unlike the standard transport which always forwards that header. Explicit jar
// cookies take precedence on key collisions.
func mergedCookies(config common.SendHttpRequestConfig) map[string]string {
	merged := make(map[string]string)
	if config.Request != nil && config.Request.Params != nil {
		for key, values := range config.Request.Params.Headers {
			if !strings.EqualFold(key, "Cookie") {
				continue
			}
			for _, value := range values {
				for name, cookieValue := range parseCookieHeader(value) {
					merged[name] = cookieValue
				}
			}
		}
	}
	for name, value := range config.Cookies {
		merged[name] = value
	}
	return merged
}

// applyCookies seeds the browser cookie jar with caller-supplied cookies scoped to
// the target URL, enabling authenticated headless crawls.
func applyCookies(page *rod.Page, targetURL string, cookies map[string]string, log svc1log.Logger) {
	if len(cookies) == 0 {
		return
	}
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for name, value := range cookies {
		params = append(params, &proto.NetworkCookieParam{
			Name:  name,
			Value: value,
			URL:   targetURL,
		})
	}
	if err := page.SetCookies(params); err != nil {
		log.Warn("Failed to set cookies on headless page", svc1log.SafeParam("error", cleanErrMsg(err)))
	}
}

// applyWebStorage injects localStorage/sessionStorage entries before any page
// script runs by registering a document-start script. This supports token-based
// auth flows that read credentials from web storage.
func applyWebStorage(page *rod.Page, localStorage map[string]string, sessionStorage map[string]string, log svc1log.Logger) {
	if len(localStorage) == 0 && len(sessionStorage) == 0 {
		return
	}
	var builder strings.Builder
	for key, value := range localStorage {
		builder.WriteString(fmt.Sprintf("try{window.localStorage.setItem(%q,%q);}catch(e){}\n", key, value))
	}
	for key, value := range sessionStorage {
		builder.WriteString(fmt.Sprintf("try{window.sessionStorage.setItem(%q,%q);}catch(e){}\n", key, value))
	}
	if _, err := (proto.PageAddScriptToEvaluateOnNewDocument{Source: builder.String()}).Call(page); err != nil {
		log.Warn("Failed to inject web storage on headless page", svc1log.SafeParam("error", cleanErrMsg(err)))
	}
}

// startConsoleCapture subscribes to console API calls and returns the accumulator.
// Returns nil when capture is disabled.
func startConsoleCapture(page *rod.Page, config common.SendHttpRequestConfig, log svc1log.Logger) *consoleCapture {
	if config.CaptureConsoleLogs == nil || !*config.CaptureConsoleLogs {
		return nil
	}
	if err := (proto.RuntimeEnable{}).Call(page); err != nil {
		log.Warn("Failed to enable runtime domain for console capture", svc1log.SafeParam("error", cleanErrMsg(err)))
	}
	capture := &consoleCapture{}
	go page.EachEvent(func(e *proto.RuntimeConsoleAPICalled) {
		parts := make([]string, 0, len(e.Args))
		for _, arg := range e.Args {
			if arg == nil {
				continue
			}
			if arg.Value.Val() != nil {
				parts = append(parts, arg.Value.Str())
			} else if arg.Description != "" {
				parts = append(parts, arg.Description)
			}
		}
		capture.add(fmt.Sprintf("[%s] %s", e.Type, strings.Join(parts, " ")))
	})()
	return capture
}

// applyPageContext applies all caller-supplied request context (headers, cookies,
// web storage) to the page prior to navigation. Each piece is additive and only
// acts when the corresponding config field is populated.
func applyPageContext(page *rod.Page, targetURL string, config common.SendHttpRequestConfig, log svc1log.Logger) {
	applyRequestHeaders(page, config, log)
	applyCookies(page, targetURL, mergedCookies(config), log)
	applyWebStorage(page, config.LocalStorage, config.SessionStorage, log)
}

// collectCookies reads the cookies set on the page after navigation, used to
// satisfy the headless_browser output contract. Returns nil when disabled.
func collectCookies(page *rod.Page, config common.SendHttpRequestConfig, log svc1log.Logger) []*common.ResponseCookie {
	if config.CaptureCookies == nil || !*config.CaptureCookies {
		return nil
	}
	cookies, err := page.Cookies([]string{})
	if err != nil {
		log.Warn("Failed to read cookies from headless page", svc1log.SafeParam("error", cleanErrMsg(err)))
		return nil
	}
	result := make([]*common.ResponseCookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		domain := cookie.Domain
		path := cookie.Path
		result = append(result, &common.ResponseCookie{
			Name:   cookie.Name,
			Value:  cookie.Value,
			Domain: &domain,
			Path:   &path,
		})
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
