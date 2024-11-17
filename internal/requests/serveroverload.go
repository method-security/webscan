package requests

import (
	"encoding/json"
	"fmt"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformServerOverloadHeaderRequests(baseURL, path, method string, payloadSize int) *webscan.MultipleRequestReport {
	report := webscan.MultipleRequestReport{}
	var errors []string

	var requestReports []*webscan.RequestReport

	serverOverloadHeaders := GenerateServerOverloadHeaders(payloadSize)
	for _, headers := range serverOverloadHeaders {
		jsonHeaders, err := json.Marshal(headers)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error marshaling headers to JSON: %v", err))
			continue
		}

		serverOverloadParams := webscan.RequestParams{}
		serverOverloadParams.HeaderParams = string(jsonHeaders)

		requestReport := PerformRequestScan(baseURL, path, method, serverOverloadParams, []string{"SERVER_OVERLOAD_HEADER_INJECTION"})
		errors = append(errors, requestReport.Errors...)
		requestReports = append(requestReports, &requestReport)
	}

	report.Requests = requestReports
	report.Errors = errors
	return &report
}

// GenerateServerOverloadHeaders dynamically generates headers based on payload size.
func GenerateServerOverloadHeaders(payloadSize int) []map[string]string {
	headersList := []map[string]string{}

	// Very large header value to test buffer limits
	headersList = append(headersList, map[string]string{
		"X-Large-Header": strings.Repeat("A", payloadSize),
	})

	// Excessive number of headers to test large header counts
	excessiveHeaders := map[string]string{}
	for i := 0; i < payloadSize; i++ {
		excessiveHeaders[fmt.Sprintf("X-Header-%d", i)] = "test"
	}
	headersList = append(headersList, excessiveHeaders)

	return headersList
}
