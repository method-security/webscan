package nuclei

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeWorkflowTemplatePathsAbsolute(t *testing.T) {
	t.Parallel()

	workflowDir := t.TempDir()
	input := []byte(`id: xss-workflow
info:
  name: XSS workflow
workflows:
  - template: subtemplates/xss-injection.yaml
    subtemplates:
      - template: subtemplates/xss-replay.yaml
`)

	got, err := makeWorkflowTemplatePathsAbsolute(input, workflowDir)
	if err != nil {
		t.Fatalf("rewrite workflow: %v", err)
	}
	for _, relative := range []string{
		"subtemplates/xss-injection.yaml",
		"subtemplates/xss-replay.yaml",
	} {
		expected := filepath.Join(workflowDir, relative)
		if !strings.Contains(string(got), expected) {
			t.Fatalf("expected rewritten workflow to contain %q, got:\n%s", expected, got)
		}
	}
}

func TestMakeWorkflowTemplatePathsAbsoluteRejectsEscape(t *testing.T) {
	t.Parallel()

	_, err := makeWorkflowTemplatePathsAbsolute(
		[]byte("workflows:\n  - template: ../outside.yaml\n"),
		t.TempDir(),
	)
	if err == nil {
		t.Fatal("expected an escaping workflow template path to fail")
	}
}
