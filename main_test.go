package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const webscanHelperProcess = "WEBSCAN_HELPER_PROCESS"
const webscanRootHelpHelperProcess = "WEBSCAN_ROOT_HELP_HELPER_PROCESS"

func TestRootHelpUsesCobraAndIncludesRodFlag(t *testing.T) {
	t.Parallel()

	cmd := exec.Command(os.Args[0], "-test.run=TestWebscanRootHelpHelperProcess")
	cmd.Env = append(os.Environ(), webscanRootHelpHelperProcess+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run root help: %v\n%s", err, output)
	}
	help := string(output)
	if !strings.Contains(help, "Usage:\n  webscan [command]") {
		t.Fatalf("expected Cobra root help, got:\n%s", help)
	}
	if !strings.Contains(help, "--rod") {
		t.Fatalf("expected Rod's global flag in Cobra help, got:\n%s", help)
	}
	if strings.Contains(help, "Usage of webscan") {
		t.Fatalf("unexpected standard-library flag help:\n%s", help)
	}
}

func TestWebscanRootHelpHelperProcess(t *testing.T) {
	if os.Getenv(webscanRootHelpHelperProcess) != "1" {
		return
	}

	os.Args = []string{"webscan", "--help"}
	main()
}

func TestDastRuntimeErrorExitsNonZero(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestWebscanHelperProcess")
	cmd.Env = append(os.Environ(),
		webscanHelperProcess+"=1",
		"WEBSCAN_TEST_OUTPUT="+filepath.Join(tempDir, "output.json"),
		"WEBSCAN_TEST_MISSING_TEMPLATE="+filepath.Join(tempDir, "missing.yaml"),
	)

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected webscan to exit nonzero when the DAST engine reports an error")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an exit error, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestWebscanHelperProcess(t *testing.T) {
	if os.Getenv(webscanHelperProcess) != "1" {
		return
	}

	os.Args = []string{
		"webscan",
		"pentest", "application", "dast",
		"--targets", "https://example.test",
		"--http-methods", "GET",
		"--template-paths", os.Getenv("WEBSCAN_TEST_MISSING_TEMPLATE"),
		"--output", "json",
		"--output-file", os.Getenv("WEBSCAN_TEST_OUTPUT"),
	}
	main()
}
