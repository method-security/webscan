package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const webscanHelperProcess = "WEBSCAN_HELPER_PROCESS"

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
