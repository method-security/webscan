package enumeratejavascript

import (
	// Standard
	"regexp"
	"strings"

	// External
	"github.com/BishopFox/jsluice"
)

// credentialNamePattern matches a configuration key whose value is a credential.
var credentialNamePattern = regexp.MustCompile(
	`(?i)(?:^|[._-]|[a-z0-9])(?:api_?key|access_?key|secret(?:_?key)?|password|passwd|pwd|` +
		`subscription_?key|client_?secret|client_?token|access_?token|auth_?token|bearer_?token|` +
		`session_?token|private_?key|signing_?key|shared_?key|sas_?token)s?$`)

// publicNamePattern matches keys that carry an identifier rather than a credential.
var publicNamePattern = regexp.MustCompile(`(?i)(?:instrumentation_?key|public_?key|client_?id|app_?id|project_?id|measurement_?id|tracking_?id)s?$`)

// opaqueValuePattern matches a value with no meaning of its own — the shape a credential has.
var opaqueValuePattern = regexp.MustCompile(`\A[A-Za-z0-9_\-+/=.]{12,}\z`)

// placeholderPattern matches values a bundle ships in place of a real credential.
var placeholderPattern = regexp.MustCompile(`(?i)\A(?:null|undefined|true|false|none|empty|changeme|placeholder|your[_-]?\w*|x{6,}|0{6,}|<[^>]*>|\$\{.*\}|#\{.*\}|%[A-Z_]+%)\z`)

// CredentialMatcher reports configuration assignments whose key names a credential and whose value
// is opaque.
//
// jsluice ships matchers for credentials with a recognisable shape — an AWS key, a GCP key, a JWT.
// A platform key is just an opaque string, so it is identifiable only by the name it is assigned to.
func CredentialMatcher() jsluice.SecretMatcher {
	return jsluice.SecretMatcher{Query: "(pair) @matches", Fn: func(node *jsluice.Node) *jsluice.Secret {
		keyNode := node.ChildByFieldName("key")
		valueNode := node.ChildByFieldName("value")
		if keyNode == nil || valueNode == nil {
			return nil
		}

		name := strings.Trim(keyNode.Content(), `"'`)
		if name == "" || publicNamePattern.MatchString(name) || !credentialNamePattern.MatchString(name) {
			return nil
		}

		if !valueNode.IsStringy() {
			return nil
		}
		value := valueNode.DecodedString()
		if !opaqueValuePattern.MatchString(value) || placeholderPattern.MatchString(value) {
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
		if credentialNamePattern.MatchString(key) {
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
