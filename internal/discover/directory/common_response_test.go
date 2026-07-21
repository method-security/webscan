package discoverdirectory

import (
	// Standard
	"context"
	"strings"
	"testing"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	"github.com/stretchr/testify/require"
)

func TestCommonResponseDetectorFiltersCalibrationProfile(t *testing.T) {
	detector := newCommonResponseDetector(0.25)
	calibration := makeResponse("/webscan-calibration-one", 200, "missing path response", "")
	candidate := makeResponse("/admin", 200, "missing page response", "")

	require.True(t, detector.Seed(calibration))
	detector.Observe(candidate)

	filteredCount, profileCount := detector.Metrics()
	require.Equal(t, 1, filteredCount)
	require.Equal(t, 1, profileCount)
	require.Empty(t, detector.Results())
}

func TestCommonResponseDetectorPromotesRepeatedCandidateProfile(t *testing.T) {
	detector := newCommonResponseDetector(0.25)
	first := makeResponse("/admin", 200, "missing /admin", "")
	second := makeResponse("/backup", 200, "missing /backup", "")

	detector.Observe(first)
	require.Len(t, detector.Results(), 1)
	filteredCount, profileCount, pendingCandidateCount := detector.ProgressMetrics()
	require.Equal(t, 0, filteredCount)
	require.Equal(t, 0, profileCount)
	require.Equal(t, 1, pendingCandidateCount)

	detector.Observe(second)

	filteredCount, profileCount = detector.Metrics()
	require.Equal(t, 2, filteredCount)
	require.Equal(t, 1, profileCount)
	require.Empty(t, detector.Results())
	_, _, pendingCandidateCount = detector.ProgressMetrics()
	require.Equal(t, 0, pendingCandidateCount)
}

func TestCommonResponseDetectorUsesBodyLengthAndWordCountTolerance(t *testing.T) {
	detector := newCommonResponseDetector(0.25)
	first := makeResponse("/admin", 200, "missing admin path", "")
	second := makeResponse("/backup", 500, "missing backup path", "")

	detector.Observe(first)
	detector.Observe(second)

	require.Empty(t, detector.Results())
	filteredCount, profileCount := detector.Metrics()
	require.Equal(t, 2, filteredCount)
	require.Equal(t, 1, profileCount)
}

func TestGroupRequestFailuresAggregatesCommonResponseMetrics(t *testing.T) {
	grouped := groupRequestFailures("https://example.com", directoryScanMetrics{
		disallowedStatusCounts: map[int]int{404: 2},
		baselineMatchCount:     3,
		commonResponseCount:    4,
		commonProfileCount:     1,
	})

	require.Len(t, grouped, 3)
	require.True(t, strings.Contains(grouped[0], "status code 404"))
	require.True(t, strings.Contains(grouped[1], "base response size/word profile"))
	require.True(t, strings.Contains(grouped[2], "4 response(s) matched 1 common response body profile"))
}

func TestAnalyzeResponseRejectsEmptyAllowedBody(t *testing.T) {
	request := makeResponse("/empty", 200, "", "")

	valid, disallowedStatus, baselineMatch, standardResponseMatch := AnalyzeResponse(context.Background(), *request, map[int]bool{200: true}, false, 0, 0, 0.25)

	require.False(t, valid)
	require.Equal(t, 0, disallowedStatus)
	require.False(t, baselineMatch)
	require.False(t, standardResponseMatch)
}

func TestAnalyzeResponseRejectsHighConfidenceStandardResponseBody(t *testing.T) {
	request := makeResponse("/missing", 200, "The requested URL was not found on this server.", "")

	valid, disallowedStatus, baselineMatch, standardResponseMatch := AnalyzeResponse(context.Background(), *request, map[int]bool{200: true}, true, 0, 0, 0.25)

	require.False(t, valid)
	require.Equal(t, 0, disallowedStatus)
	require.False(t, baselineMatch)
	require.True(t, standardResponseMatch)
}

func TestAnalyzeResponseDoesNotRejectBroadNotFoundText(t *testing.T) {
	request := makeResponse("/search", 200, "Search results: item not found in catalog", "")

	valid, disallowedStatus, baselineMatch, standardResponseMatch := AnalyzeResponse(context.Background(), *request, map[int]bool{200: true}, true, 1000, 1000, 0.25)

	require.True(t, valid)
	require.Equal(t, 0, disallowedStatus)
	require.False(t, baselineMatch)
	require.False(t, standardResponseMatch)
}

func makeResponse(path string, statusCode int, body string, redirectLocation string) *common.HttpRequestResponse {
	headers := map[string][]string{}
	if redirectLocation != "" {
		headers["Location"] = []string{redirectLocation}
	}
	response := requesthelpers.CreateHTTPResponse(statusCode, nil, headers, body)
	return &common.HttpRequestResponse{
		Request: &common.HttpRequest{
			BaseUrl: "https://example.com",
			Path:    path,
			Method:  common.HttpMethodGet,
		},
		Response: &response,
	}
}
