package enumeratejavascript_test

import (
	"strings"
	"testing"

	enumeratejavascript "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"
)

func secretValues(t *testing.T, source string) []string {
	t.Helper()
	found := []string{}
	for _, secret := range enumeratejavascript.AnalyzeSource([]byte(source), "https://app.example.com/main.js", 0, 0).Secrets {
		value := ""
		if secret.Value != nil {
			value = *secret.Value
		}
		found = append(found, secret.Kind+"|"+value)
	}
	return found
}

// A platform key is an opaque string, so the key it is assigned to is the only thing identifying it.
func TestAnalyzeSourceReportsCredentialsNamedByTheirKey(t *testing.T) {
	source := `const env={enableProdMode:!0,apiEndpoint:"https://app.example.com/api",` +
		`gatewaySubscriptionKey:"9f3e1d7c05a84b26e1c0fa93d4b87e50"};` +
		`const ciam={authority:"https://id.example.com/",clientToken:"Zq7Wm2Pk9Tn4Rb6"};`

	found := secretValues(t, source)
	for _, want := range []string{"9f3e1d7c05a84b26e1c0fa93d4b87e50", "Zq7Wm2Pk9Tn4Rb6"} {
		hit := false
		for _, key := range found {
			if strings.Contains(key, want) {
				hit = true
			}
		}
		if !hit {
			t.Fatalf("expected %s to be reported, got %v", want, found)
		}
	}
	// The endpoint alongside it is configuration, not a credential.
	for _, key := range found {
		if strings.Contains(key, "https://app.example.com/api") {
			t.Fatalf("expected the endpoint not to be reported as a credential, got %v", found)
		}
	}
}

func TestAnalyzeSourceIgnoresPublicIdentifiersAndPlaceholders(t *testing.T) {
	source := `const env={instrumentationKey:"00000000-0000-4000-8000-000000000000",` +
		`clientId:"a1b2c3d4e5f60718293a4b5c",measurementId:"G-ABCDEF1234",` +
		`apiKey:"YOUR_API_KEY_HERE",secret:"",password:"xxxxxxxxxxxx",token:"${RUNTIME_TOKEN}"};`

	if found := secretValues(t, source); len(found) != 0 {
		t.Fatalf("expected no credentials from identifiers or placeholders, got %v", found)
	}
}

// The fingerprints live in an embedded archive rebuilt by go:generate, so a stale archive would
// silently disable detection. Matching a name that exists only in the file proves it was loaded.
func TestCredentialFingerprintsAreLoadedFromTheEmbeddedConfig(t *testing.T) {
	// encryptionKey is named only in the fingerprint file, never in code.
	found := secretValues(t, `const c={encryptionKey:"a1b2c3d4e5f6a7b8c9d0"};`)
	if len(found) == 0 {
		t.Fatalf("expected a configured key name to be honored; is configs/embedded/configs.tar.gz stale?")
	}
}

// One configured name covers every spelling of it.
func TestCredentialKeyNamesMatchAcrossNamingStyles(t *testing.T) {
	for _, key := range []string{"apimSubscriptionKey", "apim_subscription_key", `"APIM-SUBSCRIPTION-KEY"`} {
		source := "const c={" + key + `:"9f3e1d7c05a84b26e1c0fa93d4b87e50"};`
		if len(secretValues(t, source)) == 0 {
			t.Fatalf("expected %s to be recognised", key)
		}
	}
}

// Short words like "true" and "none" occur inside real credentials, so they must only be rejected
// when they are the whole value.
func TestAnalyzeSourceKeepsCredentialsContainingShortPlaceholderWords(t *testing.T) {
	for _, value := range []string{"aTRUEr4ndomK3yV4l", "noneOfThisIsReal1234", "emptyR3alLookingToken9"} {
		source := "const c={apiKey:\"" + value + "\"};"
		if len(secretValues(t, source)) == 0 {
			t.Fatalf("expected %s to be reported despite containing a placeholder word", value)
		}
	}
}

// A marker still catches a placeholder however it is punctuated.
func TestAnalyzeSourceRejectsPlaceholderMarkersAcrossPunctuation(t *testing.T) {
	for _, value := range []string{"YOUR_API_KEY_HERE", "yourApiKeyHere", "change-me-before-deploy", "REPLACE_ME_NOW_PLEASE"} {
		source := "const c={apiKey:\"" + value + "\"};"
		if len(secretValues(t, source)) != 0 {
			t.Fatalf("expected %s to be rejected as a placeholder", value)
		}
	}
}

// jsluice's own matchers must keep working alongside the added one.
func TestAnalyzeSourceStillReportsShapedCredentials(t *testing.T) {
	found := secretValues(t, `const k="AKIAIOSFODNN7EXAMPLE";`)
	if len(found) == 0 {
		t.Fatalf("expected the AWS key to still be reported")
	}
}

func TestAnalyzeSourceIgnoresShortAndProseValues(t *testing.T) {
	source := `const env={apiKey:"abc",password:"correct horse battery staple"};`

	if found := secretValues(t, source); len(found) != 0 {
		t.Fatalf("expected short and prose values to be ignored, got %v", found)
	}
}

// The key a credential was assigned to and the credential itself are separate fields.
func TestAnalyzeSourceReportsNameAndValueSeparately(t *testing.T) {
	source := `const env={gatewaySubscriptionKey:"9f3e1d7c05a84b26e1c0fa93d4b87e50",apiEndpoint:"https://app.example.com/api"};`

	secrets := enumeratejavascript.AnalyzeSource([]byte(source), "https://app.example.com/main.js", 0, 0).Secrets
	if len(secrets) != 1 {
		t.Fatalf("expected exactly one secret, got %d", len(secrets))
	}

	secret := secrets[0]
	if secret.Name == nil || *secret.Name != "gatewaySubscriptionKey" {
		t.Fatalf("expected the assigned key as the name, got %v", secret.Name)
	}
	if secret.Value == nil || *secret.Value != "9f3e1d7c05a84b26e1c0fa93d4b87e50" {
		t.Fatalf("expected the bare credential as the value, got %v", secret.Value)
	}
	if secret.Context["apiEndpoint"] != "https://app.example.com/api" {
		t.Fatalf("expected the surrounding configuration as context, got %v", secret.Context)
	}
}

// A vendor matcher reports a bare key with no name of its own, which still lands in the value.
func TestAnalyzeSourceReportsShapedCredentialsAsValues(t *testing.T) {
	secrets := enumeratejavascript.AnalyzeSource([]byte(`const k="AKIAIOSFODNN7EXAMPLE";`), "https://app.example.com/main.js", 0, 0).Secrets
	if len(secrets) == 0 {
		t.Fatalf("expected the AWS key to be reported")
	}
	if secrets[0].Value == nil || *secrets[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("expected the bare AWS key as the value, got %v", secrets[0].Value)
	}
}

// A matcher returning the bundle's own object literal has no fixed key set, so the rest stays addressable.
func TestAnalyzeSourceKeepsOpenEndedPayloadsAsAttributes(t *testing.T) {
	source := `const config={apiKey:"AIzaSyC1x2v3B4n5M6q7W8e9R0t1Y2u3I4o5P6a",authDomain:"demo.firebaseapp.com",` +
		`projectId:"demo",storageBucket:"demo.appspot.com",messagingSenderId:"123456789012",appId:"1:123:web:abc"};`

	for _, secret := range enumeratejavascript.AnalyzeSource([]byte(source), "https://app.example.com/main.js", 0, 0).Secrets {
		if secret.Kind != "firebase" {
			continue
		}
		if secret.Attributes["authDomain"] != "demo.firebaseapp.com" || secret.Attributes["projectId"] != "demo" {
			t.Fatalf("expected the object's own keys to be addressable, got %v", secret.Attributes)
		}
		return
	}
	t.Fatalf("expected a firebase secret to be reported")
}
