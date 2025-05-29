package nuclei

import (
	// Standard
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
)

func ParseParameterString(b64 string) ([]*nuclei.RequestParameter, error) {
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("--dast-params must be base64 JSON: %w", err)
	}
	var wrapper struct {
		Params []*nuclei.RequestParameter `json:"params"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Params, nil
}

// ValidateProxy checks if the proxy string is a valid URL with http, https, or socks5 scheme.
func ValidateProxy(proxy string) error {
	if proxy == "" {
		return nil
	}
	parsed, err := url.Parse(proxy)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5") {
		return fmt.Errorf("--proxy must be a valid URL with http, https, or socks5 scheme")
	}
	return nil
}
