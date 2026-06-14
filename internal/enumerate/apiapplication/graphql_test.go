package apiapplication

import (
	"strings"
	"testing"
)

// TestValidateQueryOperations_AllowsReadOnly covers the scanner's correctness on documents
// that LOOK like they contain mutations or subscriptions but are actually safe to forward.
// The Bugbot review on AITF-34 PR #437 caught the original implementation misclassifying a
// fragment whose name happens to be `mutation`; these cases lock that fix in.
func TestValidateQueryOperations_AllowsReadOnly(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"plain query", `{ users { id } }`},
		{"named query", `query GetUsers { users { id } }`},
		{"named query with vars", `query GetUsers($limit: Int) { users(first: $limit) { id } }`},
		{"query with directive", `query GetUsers @cached { users { id } }`},
		{"selection field named mutation", `query GetUsers { mutation { id } }`},
		{"fragment definition", `fragment UserFields on User { id name }`},
		{"fragment with mutation as name", `fragment mutation on Query { users { id } }`},
		{"fragment with mutation as type", `fragment OnMutation on mutation { users { id } }`},
		{"query named mutation", `query mutation { users { id } }`},
		{"query named subscription", `query subscription { users { id } }`},
		{"comment containing mutation", "# mutation { evil }\nquery { users { id } }"},
		{"string containing mutation", `query { user(name: "mutation") { id } }`},
		{"block string containing mutation", `query { user(name: """mutation""") { id } }`},
		{"multiple top-level queries", `query A { x } query B { y }`},
		{"shorthand then named", `{ x } query Foo { y }`},
		{"fragment then query", `fragment F on T { x } query Q { y }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateQueryOperations(tc.query, false); err != nil {
				t.Fatalf("validateQueryOperations rejected safe query %q: %v", tc.query, err)
			}
		})
	}
}

// TestValidateQueryOperations_RejectsMutationsAndSubscriptions covers the scanner's
// rejection of TOP-LEVEL mutation/subscription operations when allowMutations is false.
func TestValidateQueryOperations_RejectsMutationsAndSubscriptions(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{"plain mutation", `mutation { createUser(name: "x") { id } }`, "mutation"},
		{"named mutation", `mutation CreateUser { createUser { id } }`, "mutation"},
		{"named mutation with vars", `mutation CreateUser($n: String!) { createUser(name: $n) { id } }`, "mutation"},
		{"plain subscription", `subscription { events { type } }`, "subscription"},
		{"named subscription", `subscription Live { events { type } }`, "subscription"},
		{"query then mutation", `query A { x } mutation B { y }`, "mutation"},
		{"comment then mutation", "# safe\nmutation Evil { x }", "mutation"},
		{"mutation with directive", `mutation @auth { createUser { id } }`, "mutation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateQueryOperations(tc.query, false)
			if err == nil {
				t.Fatalf("validateQueryOperations accepted dangerous query %q (expected reject)", tc.query)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateQueryOperations error %q does not mention %q for query %q", err.Error(), tc.want, tc.query)
			}
		})
	}
}

// TestValidateQueryOperations_AllowMutationsBypassesScanner verifies that
// allowMutations=true short-circuits the scanner entirely. The operator has opted in,
// so even documents the scanner couldn't fully validate must be forwarded.
func TestValidateQueryOperations_AllowMutationsBypassesScanner(t *testing.T) {
	cases := []string{
		`mutation { x }`,
		`subscription { events }`,
		`query A { x } mutation B { y }`,
		// Intentionally malformed: trailing junk our scanner can't classify.
		`mutation { x } extra }`,
	}
	for _, q := range cases {
		if err := validateQueryOperations(q, true); err != nil {
			t.Fatalf("validateQueryOperations rejected %q under allowMutations=true: %v", q, err)
		}
	}
}

// TestTopLevelOperationKinds_RecognizesAnonymous verifies that shorthand `{ ... }` queries
// register as anonymous operations (so they show up correctly in any future allowlist
// the gating layer may apply).
func TestTopLevelOperationKinds_RecognizesAnonymous(t *testing.T) {
	ops, err := topLevelOperationKinds(`{ x y z }`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(ops) != 1 || ops[0] != "anonymous" {
		t.Fatalf("expected [anonymous], got %v", ops)
	}
}
