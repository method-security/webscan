package nuclei

import (
	// Standard
	"fmt"
	"net/url"
	"strconv"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// External
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// hostKey extracts the host identifier from a ResultEvent.
// It prioritizes the URL host over the event host field.
func hostKey(ev *nout.ResultEvent) string {
	if u, err := url.Parse(ev.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return ev.Host
}

// toReqResp converts a Nuclei result event into an HttpRequestResponse structure.
// It parses both request and response data, including headers, body, and parameters.
func toReqResp(ev *nout.ResultEvent) (*common.HttpRequestResponse, error) {
	req := &common.HttpRequest{
		BaseHeaders: map[string][]string{},
		SentAt:      &ev.Timestamp,
	}
	resp := &common.HttpResponse{
		ResponseHeaders: map[string][]string{},
	}

	// Parse request data
	method, path, hdr, body := parseRawRequest(ev.Request)

	if m, err := common.NewHttpMethodFromString(strings.ToUpper(method)); err == nil {
		req.Method = m
	}
	req.BaseHeaders = singleToMulti(hdr)

	// Parse URL components
	if p, err := url.Parse(ev.URL); err == nil {
		req.BaseUrl = p.Scheme + "://" + p.Host
	}
	req.Path = path

	params := &common.HttpRequestParams{
		Path:  map[string]string{},
		Query: map[string]string{},
	}
	if body != "" {
		params.Body = common.NewBodyFromText(&common.TextBody{Value: body})
	}
	if u2, err := url.Parse(path); err == nil {
		for k, vs := range u2.Query() {
			if len(vs) > 0 {
				params.Query[k] = vs[0]
			}
		}
	}
	req.Params = params

	// Parse response data
	code, rh, rbody := parseRawResponse(ev.Response)
	if code != 0 {
		resp.StatusCode = &code
	}
	resp.ResponseHeaders = singleToMulti(rh)
	if rbody != "" {
		resp.SizeBytes = ptrInt(len(rbody))
		resp.ResponseBody = common.NewBodyFromText(&common.TextBody{
			Value: rbody,
		})
	}

	if ev.Error != "" {
		return nil, fmt.Errorf("nuclei: error in response: %s", ev.Error)
	}

	return &common.HttpRequestResponse{
		Request:  req,
		Response: resp,
	}, nil
}

// parseRawRequest parses a raw HTTP request string into its components.
// Returns method, path, headers, and body.
func parseRawRequest(raw string) (method, path string, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			method, path = f[0], f[1]
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

// parseRawResponse parses a raw HTTP response string into its components.
// Returns status code, headers, and body.
func parseRawResponse(raw string) (code int, headers map[string]string, body string) {
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	headers = map[string]string{}
	lines := strings.Split(parts[0], "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			if c, err := strconv.Atoi(f[1]); err == nil {
				code = c
			}
		}
		for _, h := range lines[1:] {
			if kv := strings.SplitN(h, ":", 2); len(kv) == 2 {
				headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(parts) == 2 {
		body = parts[1]
	}
	return
}

// singleToMulti converts a map of single string values to a map of string slices.
func singleToMulti(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

// strPtr returns a pointer to the given string, or nil if the string is empty.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ptrInt returns a pointer to the given integer.
func ptrInt(i int) *int { return &i }
