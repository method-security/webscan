package discoverdirectory

import (
	// Standard
	"strings"
	"sync"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

const commonResponsePromotionThreshold = 2

// responseProfile captures the same body metrics used by base response matching.
type responseProfile struct {
	BodyLength int
	WordCount  int
}

type responseCluster struct {
	profile       responseProfile
	observedPaths map[string]struct{}
	pending       []*common.HttpRequestResponse
}

// commonResponseDetector learns common responses from calibration probes and from
// repeated candidate responses observed during the scan.
type commonResponseDetector struct {
	mu sync.Mutex

	tolerance          float64
	promotionThreshold int
	knownCommon        []responseProfile
	matchedCommon      []responseProfile
	observed           []*responseCluster

	filteredResponseCount int
}

func newCommonResponseDetector(tolerance float64) *commonResponseDetector {
	return &commonResponseDetector{
		tolerance:          tolerance,
		promotionThreshold: commonResponsePromotionThreshold,
	}
}

func (d *commonResponseDetector) Seed(response *common.HttpRequestResponse) bool {
	profile, ok := buildResponseProfile(response)
	if !ok {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.knownCommon = appendUniqueProfile(d.knownCommon, profile, d.tolerance)
	return true
}

// Observe stores a candidate response until its profile is known to be unique or
// common. Once a profile repeats across distinct paths, all matching responses are
// omitted from results.
func (d *commonResponseDetector) Observe(response *common.HttpRequestResponse) {
	profile, ok := buildResponseProfile(response)
	if !ok {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if commonProfile, ok := findSimilarProfile(d.knownCommon, profile, d.tolerance); ok {
		d.matchedCommon = appendUniqueProfile(d.matchedCommon, commonProfile, d.tolerance)
		d.filteredResponseCount++
		return
	}

	cluster := d.findCluster(profile)
	if cluster == nil {
		cluster = &responseCluster{
			profile:       profile,
			observedPaths: map[string]struct{}{},
		}
		d.observed = append(d.observed, cluster)
	}

	path := ""
	if response.Request != nil {
		path = response.Request.Path
	}
	cluster.observedPaths[path] = struct{}{}
	cluster.pending = append(cluster.pending, response)

	if len(cluster.observedPaths) < d.promotionThreshold {
		return
	}

	d.knownCommon = appendUniqueProfile(d.knownCommon, cluster.profile, d.tolerance)
	d.matchedCommon = appendUniqueProfile(d.matchedCommon, cluster.profile, d.tolerance)
	d.filteredResponseCount += len(cluster.pending)
	cluster.pending = nil
}

func (d *commonResponseDetector) Results() []*common.HttpRequestResponse {
	d.mu.Lock()
	defer d.mu.Unlock()

	var results []*common.HttpRequestResponse
	for _, cluster := range d.observed {
		results = append(results, cluster.pending...)
	}
	return results
}

func (d *commonResponseDetector) Metrics() (filteredResponseCount int, profileCount int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.filteredResponseCount, len(d.matchedCommon)
}

// ProgressMetrics returns the current filter state for live scan logging.
// Pending candidates are responses that have not yet repeated enough to be
// promoted to a common response profile.
func (d *commonResponseDetector) ProgressMetrics() (filteredResponseCount int, profileCount int, pendingCandidateCount int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, cluster := range d.observed {
		pendingCandidateCount += len(cluster.pending)
	}

	return d.filteredResponseCount, len(d.matchedCommon), pendingCandidateCount
}

func (d *commonResponseDetector) findCluster(profile responseProfile) *responseCluster {
	for _, cluster := range d.observed {
		if profilesSimilar(cluster.profile, profile, d.tolerance) {
			return cluster
		}
	}
	return nil
}

func buildResponseProfile(response *common.HttpRequestResponse) (responseProfile, bool) {
	if response == nil || response.Response == nil {
		return responseProfile{}, false
	}

	body := ""
	if bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(response.Response.ResponseBody); bodyStr != nil {
		body = *bodyStr
	}

	return responseProfile{
		BodyLength: len(body),
		WordCount:  len(strings.Fields(body)),
	}, true
}

func appendUniqueProfile(profiles []responseProfile, profile responseProfile, tolerance float64) []responseProfile {
	if _, ok := findSimilarProfile(profiles, profile, tolerance); ok {
		return profiles
	}
	return append(profiles, profile)
}

func findSimilarProfile(profiles []responseProfile, profile responseProfile, tolerance float64) (responseProfile, bool) {
	for _, existing := range profiles {
		if profilesSimilar(existing, profile, tolerance) {
			return existing, true
		}
	}
	return responseProfile{}, false
}

func profilesSimilar(left, right responseProfile, tolerance float64) bool {
	return areSimilar(left.BodyLength, right.BodyLength, tolerance) &&
		areSimilar(left.WordCount, right.WordCount, tolerance)
}
