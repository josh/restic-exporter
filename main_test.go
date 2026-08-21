package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func clearResticEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(key, "RESTIC_") {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset %s failed: %v", key, err)
			}
		}
	}
}

func metricValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metric:
		for _, m := range mf.GetMetric() {
			for k, want := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == want {
						found = true
						break
					}
				}
				if !found {
					continue metric
				}
			}
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func applyEnv(t *testing.T, env []string) {
	t.Helper()
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		t.Setenv(parts[0], parts[1])
	}
}

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
	clearResticEnv(t)
	repoDir := filepath.Join(t.TempDir(), "repo")
	dataDir := filepath.Join(t.TempDir(), "data")
	defer func() { _ = os.RemoveAll(dataDir) }()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	env := []string{
		"RESTIC_REPOSITORY=" + repoDir,
		"RESTIC_PASSWORD=password",
		"RESTIC_CACHE_DIR=" + filepath.Join(t.TempDir(), "cache"),
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

func TestRejectsInvalidRefreshInterval(t *testing.T) {
	clearResticEnv(t)
	t.Setenv("RESTIC_REPOSITORY", filepath.Join(t.TempDir(), "repo"))
	t.Setenv("RESTIC_PASSWORD", "password")

	for _, interval := range []string{"0", "-5", "10000000000"} {
		if code := run([]string{"--refresh-interval", interval}); code != 1 {
			t.Fatalf("run() with --refresh-interval %s returned %d, want 1", interval, code)
		}
	}
}

func TestGenerateMetricsOutputFromLocalResticRepo(t *testing.T) {
	env := initLocalResticRepo(t)

	outputFile := filepath.Join(t.TempDir(), "metrics.prom")
	applyEnv(t, env)
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

func TestCountStaleLocks(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		times []time.Time
		want  int
	}{
		{"no locks", nil, 0},
		{"fresh lock", []time.Time{now.Add(-5 * time.Minute)}, 0},
		{"exactly at timeout", []time.Time{now.Add(-30 * time.Minute)}, 0},
		{"just past timeout", []time.Time{now.Add(-30*time.Minute - time.Second)}, 1},
		{"clock skew into the future", []time.Time{now.Add(time.Hour)}, 0},
		{
			"mixed",
			[]time.Time{now.Add(-time.Minute), now.Add(-time.Hour), now.Add(-48 * time.Hour)},
			2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := countStaleLocks(tc.times, now); got != tc.want {
				t.Fatalf("countStaleLocks() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestLockMetricsOnUnlockedRepo(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))

	if err := updateResticMetrics(config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}

	for name, want := range map[string]float64{
		"restic_locks_total":       0,
		"restic_stale_locks_total": 0,
	} {
		got, ok := metricValue(t, name, nil)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		if got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
}

func TestLockMetricsWithHeldLock(t *testing.T) {
	env := initLocalResticRepo(t)
	applyEnv(t, env)

	cmd := exec.Command("restic", "backup", "--stdin", "--stdin-filename", "held")
	cmd.Env = append(os.Environ(), env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe failed: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("restic backup --stdin failed to start: %v", err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	}()

	deadline := time.Now().Add(30 * time.Second)
	var ids []string
	for time.Now().Before(deadline) {
		if ids, err = getLockIDs(); err != nil {
			t.Fatalf("getLockIDs() failed: %v", err)
		}
		if len(ids) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(ids) == 0 {
		t.Skip("restic did not take a lock within the deadline")
	}

	if err := updateResticMetrics(config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	if got, _ := metricValue(t, "restic_locks_total", nil); got < 1 {
		t.Fatalf("restic_locks_total = %v, want at least 1", got)
	}
	if got, _ := metricValue(t, "restic_stale_locks_total", nil); got != 0 {
		t.Fatalf("restic_stale_locks_total = %v, want 0 for a freshly held lock", got)
	}

	original := staleLockTimeout
	staleLockTimeout = -time.Second
	defer func() { staleLockTimeout = original }()

	if err := updateResticMetrics(config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	if got, _ := metricValue(t, "restic_stale_locks_total", nil); got < 1 {
		t.Fatalf("restic_stale_locks_total = %v, want at least 1 with a negative timeout", got)
	}
}
