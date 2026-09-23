package enumeratejavascript

import (
	// Standard
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	// Configs
	"github.com/Method-Security/webscan/configs"
	// External
	"github.com/BishopFox/jsluice"
)

// credentialKeysPath is the fingerprint file naming the configuration keys that hold a credential.
const credentialKeysPath = "enumerate/javascript/credential_keys.json"

// credentialKeys is the fingerprint file's contents.
type credentialKeys struct {
	CredentialKeyNames []string `json:"credentialKeyNames"`
	PublicKeyNames     []string `json:"publicKeyNames"`
	PlaceholderValues  []string `json:"placeholderValues"`
	MinimumValueLength int      `json:"minimumValueLength"`
}

var (
	loadKeysOnce sync.Once
	loadedKeys   credentialKeys
)

// opaqueValuePattern matches a value with no meaning of its own — the shape a credential has.
var opaqueValuePattern = regexp.MustCompile(`\A[A-Za-z0-9_\-+/=.]+\z`)

// templatedValuePattern matches a value substituted at deploy time rather than shipped.
var templatedValuePattern = regexp.MustCompile(`\A(?:\$\{.*\}|#\{.*\}|%[A-Za-z_]+%|<[^>]*>|x{6,}|0{6,})\z`)

func credentialFingerprints() credentialKeys {
	loadKeysOnce.Do(func() {
		data, err := configs.ReadFile(credentialKeysPath)
		if err != nil {
			return
		}
		_ = json.Unmarshal(data, &loadedKeys)
	})
	return loadedKeys
}

// normalizeKeyName reduces a key to a comparable form, so one configured name covers the camelCase,
// snake_case and kebab-case spellings of it.
func normalizeKeyName(name string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(name) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

// namesACredential reports a key whose value is a credential rather than an identifier.
func namesACredential(name string) bool {
	normalized := normalizeKeyName(name)
	if normalized == "" {
		return false
	}

	fingerprints := credentialFingerprints()
	for _, public := range fingerprints.PublicKeyNames {
		if strings.HasSuffix(normalized, normalizeKeyName(public)) {
			return false
		}
	}
	for _, credential := range fingerprints.CredentialKeyNames {
		if strings.HasSuffix(normalized, normalizeKeyName(credential)) {
			return true
		}
	}
	return false
}

// isShippedCredential reports a value that is a credential rather than a placeholder.
func isShippedCredential(value string) bool {
	fingerprints := credentialFingerprints()
	if len(value) < fingerprints.MinimumValueLength {
		return false
	}
	if !opaqueValuePattern.MatchString(value) || templatedValuePattern.MatchString(value) {
		return false
	}
	for _, placeholder := range fingerprints.PlaceholderValues {
		if strings.EqualFold(value, placeholder) {
			return false
		}
	}
	// A placeholder often names itself, e.g. YOUR_API_KEY_HERE.
	lowered := strings.ToLower(value)
	for _, placeholder := range fingerprints.PlaceholderValues {
		if strings.Contains(lowered, strings.ToLower(placeholder)) {
			return false
		}
	}
	return !strings.HasPrefix(lowered, "your")
}

// CredentialMatcher reports configuration assignments whose key names a credential and whose value
// is opaque.
//
// jsluice ships matchers for credentials with a recognisable shape — an AWS key, a GCP key, a JWT.
// A platform key is just an opaque string, so it is identifiable only by the name it is assigned to,
// and those names live in configs/enumerate/javascript/credential_keys.json.
func CredentialMatcher() jsluice.SecretMatcher {
	return jsluice.SecretMatcher{Query: "(pair) @matches", Fn: func(node *jsluice.Node) *jsluice.Secret {
		keyNode := node.ChildByFieldName("key")
		valueNode := node.ChildByFieldName("value")
		if keyNode == nil || valueNode == nil {
			return nil
		}

		name := strings.Trim(keyNode.Content(), `"'`)
		if !namesACredential(name) {
			return nil
		}
		if !valueNode.IsStringy() {
			return nil
		}
		value := valueNode.DecodedString()
		if !isShippedCredential(value) {
			return nil
		}

		return &jsluice.Secret{
			Kind:    "configuredCredential",
			Data:    map[string]string{"name": name, "value": value},
			Context: credentialContext(node),
		}
	}}
}

// credentialContext returns the object the assignment sits in, so a reviewer can see what the
// credential belongs to without the bundle in front of them.
func credentialContext(node *jsluice.Node) map[string]string {
	parent := node.Parent()
	if parent == nil || parent.Type() != "object" {
		return nil
	}

	context := map[string]string{}
	for key, value := range parent.AsObject().AsMap() {
		if namesACredential(key) {
			continue
		}
		if len(value) > 120 {
			value = value[:120]
		}
		context[key] = value
	}
	if len(context) == 0 {
		return nil
	}
	return context
}
