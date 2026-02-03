package discoverpage

import (
	"context"
	"regexp"

	// Generated
	"github.com/Method-Security/webscan/generated/go/discover"

	//External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TokenFingerprints using Fern-generated types
var TokenFingerprints = discover.TokenFingerprints{
	Fingerprints: []*discover.TokenFingerprint{
		// High confidence - most reliable patterns with low false positives
		{Type: "aws_access_key", Pattern: `\b(AKIA[0-9A-Z]{16})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "aws_session_key", Pattern: `\b(ASIA[0-9A-Z]{16})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "github_token", Pattern: `\b(gh[pousr]_[A-Za-z0-9]{36})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "github_pat", Pattern: `\b(ghp_[A-Za-z0-9]{36})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "stripe_key", Pattern: `(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "sendgrid_key", Pattern: `(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "anthropic_key", Pattern: `(sk-ant-[a-zA-Z0-9]{6,8}-[\w\-]{90,95}[A-Z]{2})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "databricks_token", Pattern: `\b(dapi[0-9a-f]{32})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "notion_token", Pattern: `\b(secret_[A-Za-z0-9]{43})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "linear_key", Pattern: `\b(lin_api_[0-9A-Za-z]{40})\b`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "mailgun_key", Pattern: `\b(key-[0-9a-f]{32})\b`, Confidence: discover.TokenConfidenceLevelHigh},

		// Medium confidence
		{Type: "slack_token", Pattern: `(xox[baprs]-[0-9a-zA-Z\-]{20,})`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "private_key", Pattern: `(-----BEGIN[A-Z ]+PRIVATE KEY-----[\s\S]*?-----END[A-Z ]+PRIVATE KEY-----)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "mongodb_uri", Pattern: `(mongodb(?:\+srv)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "postgres_uri", Pattern: `(postgres(?:ql)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "mysql_uri", Pattern: `(mysql://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "redis_uri", Pattern: `(redis[s]?://[^/\s:]*:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "slack_webhook", Pattern: `(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`, Confidence: discover.TokenConfidenceLevelMedium},

		// To-Do: Low confidence once noise level is judged on the above Fingerprints
	},
}

// ExtractTokensFromWebContent searches for tokens in web content
func ExtractTokensFromWebContent(ctx context.Context, content string) ([]*discover.ExposedToken, []string) {
	log := svc1log.FromContext(ctx)

	var tokens []*discover.ExposedToken
	var errors []string

	for _, fingerprint := range TokenFingerprints.Fingerprints {
		// Compile the pattern string into a regex
		compiledPattern, err := regexp.Compile(fingerprint.Pattern)
		if err != nil {
			log.Error("Failed to compile pattern", svc1log.SafeParam("error", err))
			errors = append(errors, err.Error())
			continue // Skip invalid patterns
		}

		matches := compiledPattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				log.Info("Found token", svc1log.SafeParam("token", match[1]))
				value := match[1]

				token := discover.ExposedToken{
					Value:       value,
					Fingerprint: fingerprint,
				}

				tokens = append(tokens, &token)
			}
		}
	}

	return tokens, errors
}
