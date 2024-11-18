package requests

import (
	"encoding/json"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformServerOverloadHeaderRequests(baseURL, path, method string, headerNames []string, payloadSize int, vulnTypes []string) webscan.RequestReport {
	params := webscan.RequestParams{}
	params.HeaderParams = GenerateServerOverloadHeaders(headerNames, payloadSize)
	return PerformRequestScan(baseURL, path, method, params, vulnTypes)
}

func GenerateServerOverloadHeaders(headerNames []string, payloadSize int) string {
	headers := make(map[string]string)
	payload := strings.Repeat("A", payloadSize)

	for _, headerName := range headerNames {
		headers[headerName] = payload
	}

	jsonHeaders, err := json.Marshal(headers)
	if err != nil {
		return "{}"
	}

	return string(jsonHeaders)
}
