package enumeratejavascript_test

import (
	"strings"
	"testing"

	enumeratejavascript "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"
)

func secretValues(t *testing.T, source string) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, secret := range enumeratejavascript.AnalyzeSource([]byte(source), "https://app.example.com/main.js", 0, 0).Secrets {
		value := ""
		if secret.Value != nil {
			value = *secret.Value
		}
		found[secret.Kind+"|"+value] = string(secret.Severity)
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
		for key, severity := range found {
			if strings.Contains(key, want) && severity == "HIGH" {
				hit = true
			}
		}
		if !hit {
			t.Fatalf("expected %s to be reported as HIGH, got %v", want, found)
		}
	}
	// The endpoint alongside it is configuration, not a credential.
	for key := range found {
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
