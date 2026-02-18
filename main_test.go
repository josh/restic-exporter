package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func runCommand(t *testing.T, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\n%s", name, strings.Join(args, " "), string(out))
	}
	return string(out)
}

func initLocalResticRepo(t *testing.T) []string {
	t.Helper()
	repoDir := filepath.Join(t.TempDir(), "repo")
	dataDir := filepath.Join(t.TempDir(), "data")
	defer func() { _ = os.RemoveAll(dataDir) }()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	env := []string{
		"RESTIC_REPOSITORY=" + repoDir,
		"RESTIC_PASSWORD=password",
	}
	runCommand(t, env, "restic", "init")

	if err := os.WriteFile(filepath.Join(dataDir, "file.txt"), []byte("first snapshot\n"), 0o600); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	runCommand(t, env, "restic", "backup", dataDir)

	if err := os.WriteFile(filepath.Join(dataDir, "file.txt"), []byte("second snapshot\n"), 0o600); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	runCommand(t, env, "restic", "backup", dataDir)

	return env
}

func TestGenerateMetricsOutputFromLocalResticRepo(t *testing.T) {
	env := initLocalResticRepo(t)

	outputFile := filepath.Join(t.TempDir(), "metrics.prom")
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		t.Setenv(parts[0], parts[1])
	}
	if code := run([]string{"--output", outputFile}); code != 0 {
		t.Fatalf("run() returned non-zero exit code: %d", code)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	output := string(data)
	if !strings.Contains(output, "restic_backup_snapshots_total") {
		t.Fatalf("expected backup snapshot metric family, got:\n%s", output)
	}

	re := regexp.MustCompile(`restic_backup_snapshots_total\{[^\n]*\}\s+2`)
	if !re.MatchString(output) {
		t.Fatalf("expected deduplicated snapshot counter value 2, got:\n%s", output)
	}

	globalSnapshots := regexp.MustCompile(`(?m)^restic_snapshots_total\s+[1-9][0-9]*(\.[0-9]+)?$`)
	if !globalSnapshots.MatchString(output) {
		t.Fatalf("expected positive restic_snapshots_total metric, got:\n%s", output)
	}
}
