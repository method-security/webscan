package discoverpage

import (
	"context"
	"regexp"

	// Generated
	"github.com/Method-Security/webscan/generated/go/discover"

	//External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// SensitiveContextFingerprints using Fern-generated types
var SensitiveContextFingerprints = discover.SensitiveContextFingerprints{
	Fingerprints: []*discover.SensitiveContextFingerprint{
		// High confidence - most reliable patterns with low false positives
		{Type: "anthropic_key", Pattern: `(sk-ant-[a-zA-Z0-9]{6,8}-[\w\-]{90,95}[A-Z]{2})`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "aws_access_key", Pattern: `\b(AKIA[0-9A-Z]{16})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "aws_session_key", Pattern: `\b(ASIA[0-9A-Z]{16})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "databricks_token", Pattern: `\b(dapi[0-9a-f]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "figma_token", Pattern: `\b(fig[d|((u|o)(r|h)?)]_[a-z0-9A-Z_-]{40})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "github_pat", Pattern: `\b(ghp_[A-Za-z0-9]{36})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "github_token", Pattern: `\b(gh[pousr]_[A-Za-z0-9]{36})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "grafana_service_token", Pattern: `\b(glsa_[0-9a-zA-Z_]{41})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "linear_key", Pattern: `\b(lin_api_[0-9A-Za-z]{40})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "mailgun_key", Pattern: `\b(key-[0-9a-f]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "notion_token", Pattern: `\b(secret_[A-Za-z0-9]{43})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "openai_api_key", Pattern: `\b(sk-[a-zA-Z0-9]{48})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "sendgrid_key", Pattern: `(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "shopify_token", Pattern: `\b(shp[a-z]{2}_[a-fA-F0-9]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "square_token", Pattern: `\b(sq0idp-[0-9A-Za-z]{22})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "stripe_key", Pattern: `(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Type: "twilio_api_key", Pattern: `\b(SK[0-9a-f]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},

		// Medium confidence
		{Type: "mongodb_uri", Pattern: `(mongodb(?:\+srv)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Type: "mysql_uri", Pattern: `(mysql://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Type: "postgres_uri", Pattern: `(postgres(?:ql)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Type: "private_key", Pattern: `(-----BEGIN[A-Z ]+PRIVATE KEY-----[\s\S]*?-----END[A-Z ]+PRIVATE KEY-----)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Type: "redis_uri", Pattern: `(redis[s]?://[^/\s:]*:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Type: "slack_token", Pattern: `(xox[baprs]-[0-9a-zA-Z\-]{20,})`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Type: "slack_webhook", Pattern: `(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`, Confidence: discover.SensitiveContextConfidenceLevelMedium},

		// To-Do: Low confidence once noise level is judged on the above Fingerprints
	},
}

// ExtractTokensFromWebContent searches for tokens in web content
func ExtractSensitiveContextsFromWebContent(ctx context.Context, content string) ([]*discover.SensitiveContext, []string) {
	log := svc1log.FromContext(ctx)

	var sensitiveContextValues []*discover.SensitiveContext
	var errors []string

	for _, fingerprint := range SensitiveContextFingerprints.Fingerprints {
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
				log.Info("Found token", svc1log.SafeParam("type", fingerprint.Type))
				value := match[1]

				sensitiveContext := discover.SensitiveContext{
					Value:       value,
					Fingerprint: fingerprint,
				}

				sensitiveContextValues = append(sensitiveContextValues, &sensitiveContext)
			}
		}
	}

	return sensitiveContextValues, errors
}
