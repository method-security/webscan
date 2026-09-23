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
