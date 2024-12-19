package fingerprint

import (
	"context"
	"crypto/tls"
	"net/http"

	webscan "github.com/Method-Security/webscan/generated/go/url"
)

// performOptionsRequest performs an OPTIONS request against a target URL and captures the HTTP headers
func performOptionsRequest(target string) (*webscan.HttpHeaders, error) {
	req, err := http.NewRequest("OPTIONS", target, nil)
	if err != nil {
		return &webscan.HttpHeaders{}, err
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Prevent following redirects
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return &webscan.HttpHeaders{}, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()
	if err != nil {
		return &webscan.HttpHeaders{}, err
	}

	httpHeaders := assignHeaders(resp.Header)

	return httpHeaders, nil
}

// PerformTlsInspedction performs a TLS inspection against a target URL and captures the TLS information
func performTLSInspection(target string) (*webscan.TlsInfo, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		return &webscan.TlsInfo{}, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()
	if err != nil {
		return &webscan.TlsInfo{}, err
	}

	state := resp.TLS
	if state == nil {
		return &webscan.TlsInfo{}, err
	}

	tlsInfo := convertToTLSInfo(state)

	return tlsInfo, nil
}

// PerformFingerprint performs a path fuzzing operation against a target URL, using the provided pathlist and responsecodes
func PerformFingerprint(ctx context.Context, target string) webscan.UrlFingerprintReport {
	report := webscan.UrlFingerprintReport{
		Target: target,
		Errors: []string{},
	}

	// Perform OPTIONS request
	httpHeaders, err := performOptionsRequest(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.HttpHeaders = httpHeaders
	}

	// Perform TLS inspection
	tlsInfo, err := performTLSInspection(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.TlsInfo = tlsInfo
	}

	// Check if there was a redirect and if so follow the redirect and perform another OPTIONS request
	// And TLS inspection
	if httpHeaders.Location != nil && httpHeaders.Location != &target {
		redirectHTTPHeaders, err := performOptionsRequest(*httpHeaders.Location)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.RedirectUrl = httpHeaders.Location
			report.RedirectHttpHeaders = redirectHTTPHeaders
		}

		// Perform TLS inspection
		redirectTLSInfo, err := performTLSInspection(*httpHeaders.Location)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			report.RedirectTlsInfo = redirectTLSInfo
		}
	}

	return report
}
