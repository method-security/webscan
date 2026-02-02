package discoverpage

import (
	"regexp"
	"strings"

	// Generated
	"github.com/Method-Security/webscan/generated/go/discover"
)

// TokenFingerprints using Fern-generated types
var TokenFingerprints = discover.TokenFingerprints{
	Fingerprints: []*discover.TokenFingerprint{
		// High confidence - specific, well-known patterns
		{Type: "aws_access_key", Pattern: `(AKIA[0-9A-Z]{16})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "aws_session_key", Pattern: `(ASIA[0-9A-Z]{16})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "github_token", Pattern: `(gh[pousr]_[A-Za-z0-9]{36})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "github_pat", Pattern: `(ghp_[A-Za-z0-9]{36})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "slack_token", Pattern: `(xox[baprs]-[0-9a-zA-Z\-]{8,})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "stripe_key", Pattern: `(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "stripe_webhook", Pattern: `(whsec_[A-Za-z0-9]{32,})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "google_api", Pattern: `(AIza[0-9A-Za-z\-_]{35})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "sendgrid_key", Pattern: `(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "jwt_token", Pattern: `(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*)`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "private_key", Pattern: `(?s)(-----BEGIN[A-Z ]+PRIVATE KEY-----.*?-----END[A-Z ]+PRIVATE KEY-----)`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "anthropic_key", Pattern: `(sk-ant-[a-zA-Z0-9]{6,8}-[\w\-]{90,95}[A-Z]{2})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "openai_key", Pattern: `(sk-[A-Za-z0-9]{48})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "discord_token", Pattern: `([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "square_token", Pattern: `(sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "twilio_sid", Pattern: `(AC[0-9a-f]{32})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "facebook_token", Pattern: `(EAA[A-Za-z0-9]{100,})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "databricks_token", Pattern: `(dapi[0-9a-f]{32})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "notion_token", Pattern: `(secret_[A-Za-z0-9]{43})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "figma_token", Pattern: `(figd_[A-Za-z0-9_-]{43})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "linear_key", Pattern: `(lin_api_[0-9A-Za-z]{40})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "telegram_token", Pattern: `([0-9]{8,10}:[a-zA-Z0-9_-]{35})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "mailgun_key", Pattern: `(key-[0-9a-f]{32})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "npm_token", Pattern: `(npm_[A-Za-z0-9]{36})`, Confidence: discover.TokenConfidenceLevelHigh},
		{Type: "pypi_token", Pattern: `(pypi-AgEI[A-Za-z0-9_-]{150,})`, Confidence: discover.TokenConfidenceLevelHigh},

		// Medium confidence - connection strings and webhooks
		{Type: "url_with_creds", Pattern: `(https?://[^/\s:]+:[^/\s@]+@[^\s'"]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "mongodb_uri", Pattern: `(mongodb(?:\+srv)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "postgres_uri", Pattern: `(postgres(?:ql)?://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "mysql_uri", Pattern: `(mysql://[^/\s:]+:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "redis_uri", Pattern: `(redis[s]?://[^/\s:]*:[^/\s@]+@[^\s'"/?]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "slack_webhook", Pattern: `(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "discord_webhook", Pattern: `(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "docker_auth", Pattern: `(?i)"auths"[^}]*"auth"[^"]*"([A-Za-z0-9+/]+=*?)"`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "bearer_token", Pattern: `(?i)bearer\s+([A-Za-z0-9\-_.+/]{20,})`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "basic_auth", Pattern: `(?i)basic\s+([A-Za-z0-9+/]+=*)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "ftp_with_creds", Pattern: `(ftp://[^/\s:]+:[^/\s@]+@[^\s'"]+)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "elasticsearch_uri", Pattern: `(https?://[^/\s:]+:[^/\s@]+@[^/\s]+:9200)`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "influxdb_token", Pattern: `([A-Za-z0-9_-]{88})`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "circleci_token", Pattern: `([a-fA-F0-9]{40})`, Confidence: discover.TokenConfidenceLevelMedium},
		{Type: "travis_token", Pattern: `([a-zA-Z0-9_]{22})`, Confidence: discover.TokenConfidenceLevelMedium},

		// Low confidence - generic patterns that may have false positives
		{Type: "generic_api_key", Pattern: `(?i)api[_-]?key['":\s]*[=:]\s*['"]*([0-9a-zA-Z\-_.+/]{20,})['"]*`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "generic_token", Pattern: `(?i)token['":\s]*[=:]\s*['"]*([0-9a-zA-Z\-_.+/]{20,})['"]*`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "generic_secret", Pattern: `(?i)secret['":\s]*[=:]\s*['"]*([0-9a-zA-Z\-_.+/]{20,})['"]*`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "generic_password", Pattern: `(?i)password['":\s]*[=:]\s*['"]*([^'"\s]{8,})['"]*`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "uuid_token", Pattern: `([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "base64_token", Pattern: `([A-Za-z0-9+/]{64,}={0,2})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "hex_token", Pattern: `([a-f0-9]{40,})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "mailchimp_key", Pattern: `([0-9a-f]{32}-us[0-9]{1,2})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "mixpanel_key", Pattern: `([a-zA-Z0-9-]{32})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "newrelic_key", Pattern: `([A-Za-z0-9_\.]{4}-[A-Za-z0-9_\.]{42})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "postmark_token", Pattern: `([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "sendinblue_key", Pattern: `(xkeysib-[A-Za-z0-9_-]{81})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "elastic_email", Pattern: `([A-Za-z0-9_-]{96})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "hunter_key", Pattern: `([a-z0-9_-]{40})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "loadmill_token", Pattern: `([0-9a-zA-Z]{40})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "abstract_key", Pattern: `([0-9a-z]{32})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "vercel_token", Pattern: `([a-zA-Z0-9]{24})`, Confidence: discover.TokenConfidenceLevelLow},
		{Type: "railway_token", Pattern: `([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`, Confidence: discover.TokenConfidenceLevelLow},
	},
}

// ExtractTokensFromWebContent searches for tokens in web content
func ExtractTokensFromWebContent(content string) []discover.ExposedToken {
	var tokens []discover.ExposedToken

	for _, fingerprint := range TokenFingerprints.Fingerprints {
		// Compile the pattern string into a regex
		compiledPattern, err := regexp.Compile(fingerprint.Pattern)
		if err != nil {
			continue // Skip invalid patterns
		}

		matches := compiledPattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				value := match[1]

				token := discover.ExposedToken{
					Value:       value,
					Fingerprint: fingerprint,
				}

				tokens = append(tokens, token)
			}
		}
	}

	return tokens
}

// getContext extracts surrounding text
func getContext(content, match string, contextLength int) string {
	index := strings.Index(content, match)
	if index == -1 {
		return ""
	}

	start := index - contextLength
	if start < 0 {
		start = 0
	}

	end := index + len(match) + contextLength
	if end > len(content) {
		end = len(content)
	}

	context := content[start:end]
	context = strings.ReplaceAll(context, "\n", " ")
	context = strings.ReplaceAll(context, "\t", " ")
	context = regexp.MustCompile(`\s+`).ReplaceAllString(context, " ")

	return strings.TrimSpace(context)
}
