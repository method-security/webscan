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
		// To-Do: Add PII_DATA detection patterns

		// High confidence - most reliable patterns with low false positives
		// Credentials
		{Name: "anthropic_key", Type: discover.SensitiveContextTypeCredential, Pattern: `(sk-ant-[a-zA-Z0-9]{6,8}-[\w\-]{90,95}[A-Z]{2})`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "aws_access_key", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(AKIA[0-9A-Z]{16})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "aws_session_key", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(ASIA[0-9A-Z]{16})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "databricks_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(dapi[0-9a-f]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "figma_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(fig(?:d|(?:u|o)(?:r|h)?)_[a-z0-9A-Z_-]{40})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "github_pat", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(ghp_[A-Za-z0-9]{36})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "github_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(gh[pousr]_[A-Za-z0-9]{36})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "grafana_service_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(glsa_[0-9a-zA-Z_]{41})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "linear_key", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(lin_api_[0-9A-Za-z]{40})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "mailgun_key", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(key-[0-9a-f]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "notion_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(secret_[A-Za-z0-9]{43})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "openai_api_key", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(sk-[a-zA-Z0-9]{48})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "sendgrid_key", Type: discover.SensitiveContextTypeCredential, Pattern: `(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "shopify_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(shp[a-z]{2}_[a-fA-F0-9]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "square_token", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(sq0idp-[0-9A-Za-z]{22})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "stripe_key", Type: discover.SensitiveContextTypeCredential, Pattern: `(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})`, Confidence: discover.SensitiveContextConfidenceLevelHigh},
		{Name: "twilio_api_key", Type: discover.SensitiveContextTypeCredential, Pattern: `\b(SK[0-9a-f]{32})\b`, Confidence: discover.SensitiveContextConfidenceLevelHigh},

		// Medium confidence
		// Credentials
		{Name: "mongodb_uri", Type: discover.SensitiveContextTypeCredential, Pattern: `(mongodb(?:\+srv)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Name: "mysql_uri", Type: discover.SensitiveContextTypeCredential, Pattern: `(mysql://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Name: "postgres_uri", Type: discover.SensitiveContextTypeCredential, Pattern: `(postgres(?:ql)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Name: "private_key", Type: discover.SensitiveContextTypeCredential, Pattern: `(-----BEGIN[A-Z ]+PRIVATE KEY-----[\s\S]*?-----END[A-Z ]+PRIVATE KEY-----)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Name: "redis_uri", Type: discover.SensitiveContextTypeCredential, Pattern: `(redis[s]?://[^/\s:]*:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Name: "slack_token", Type: discover.SensitiveContextTypeCredential, Pattern: `(xox[baprs]-[0-9a-zA-Z\-]{20,})`, Confidence: discover.SensitiveContextConfidenceLevelMedium},
		{Name: "slack_webhook", Type: discover.SensitiveContextTypeCredential, Pattern: `(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`, Confidence: discover.SensitiveContextConfidenceLevelMedium},

		// To-Do: Low confidence once noise level is judged on the above sensitive context fingerprints
	},
}

// ExtractSensitiveContextsFromWebContent searches for sensitive contexts in web content
func ExtractSensitiveContextsFromWebContent(ctx context.Context, content string) ([]*discover.SensitiveContext, []string) {
	log := svc1log.FromContext(ctx)

	var sensitiveContextValues []*discover.SensitiveContext
	var errors []string
	seen := make(map[string]bool) // Track unique credential values

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
				value := match[1]

				// Skip if we've already seen this credential value
				if seen[value] {
					log.Info("Skipping duplicate token", svc1log.SafeParam("type", fingerprint.Type))
					continue
				}

				log.Info("Found token", svc1log.SafeParam("type", fingerprint.Type))
				seen[value] = true

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
