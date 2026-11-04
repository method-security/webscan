package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const webscanHelperProcess = "WEBSCAN_HELPER_PROCESS"
const webscanGraphQLHelperProcess = "WEBSCAN_GRAPHQL_HELPER_PROCESS"

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

func TestGraphQLHTTPErrorExitsZero(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestWebscanGraphQLHelperProcess")
	cmd.Env = append(os.Environ(),
		webscanGraphQLHelperProcess+"=1",
		"WEBSCAN_TEST_GRAPHQL_TARGET="+server.URL,
		"WEBSCAN_TEST_OUTPUT="+filepath.Join(tempDir, "output.json"),
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected webscan to exit 0 when the GraphQL endpoint returns 404, got %v: %s", err, output)
	}
}

func TestWebscanGraphQLHelperProcess(t *testing.T) {
	if os.Getenv(webscanGraphQLHelperProcess) != "1" {
		return
	}

	os.Args = []string{
		"webscan",
		"enumerate", "api-application", "graphql",
		"--target", os.Getenv("WEBSCAN_TEST_GRAPHQL_TARGET"),
		"--output", "json",
		"--output-file", os.Getenv("WEBSCAN_TEST_OUTPUT"),
	}
	main()
}
