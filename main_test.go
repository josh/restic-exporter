package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/josh/restic-api/api/archiver"
	"github.com/josh/restic-api/api/backend/all"
	"github.com/josh/restic-api/api/data"
	"github.com/josh/restic-api/api/fs"
	"github.com/josh/restic-api/api/global"
	"github.com/josh/restic-api/api/repository"
	"github.com/josh/restic-api/api/restic"
	"github.com/josh/restic-api/api/ui"
	"github.com/josh/restic-api/api/ui/progress"
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

func initLocalResticRepo(t *testing.T) []string {
	t.Helper()
	clearResticEnv(t)
	ctx := context.Background()
	repoDir := filepath.Join(t.TempDir(), "repo")
	dataDir := filepath.Join(t.TempDir(), "data")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	defer func() { _ = os.RemoveAll(dataDir) }()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	gopts := global.Options{
		Repo:     repoDir,
		CacheDir: cacheDir,
		Password: "password",
		Term:     &ui.MockTerminal{},
		Backends: all.Backends(),
	}
	repo, err := global.CreateRepository(ctx, gopts, restic.StableRepoVersion, nil, &progress.NoopPrinter{})
	if err != nil {
		t.Fatalf("create repository failed: %v", err)
	}
	defer func() { _ = repo.Close() }()

	for _, content := range []string{"first snapshot\n", "second snapshot\n"} {
		if err := os.WriteFile(filepath.Join(dataDir, "file.txt"), []byte(content), 0o600); err != nil {
			t.Fatalf("write file failed: %v", err)
		}
		arch := archiver.New(repo, fs.Local{}, archiver.Options{})
		now := time.Now()
		_, _, _, err := arch.Snapshot(ctx, []string{dataDir}, archiver.SnapshotOptions{
			Time:           now,
			BackupStart:    now,
			Hostname:       "testhost",
			Tags:           data.TagList{"tag2", "tag1"},
			ProgramVersion: "restic " + global.Version,
		})
		if err != nil {
			t.Fatalf("snapshot failed: %v", err)
		}
	}

	return []string{
		"RESTIC_REPOSITORY=" + repoDir,
		"RESTIC_PASSWORD=password",
		"RESTIC_CACHE_DIR=" + cacheDir,
	}
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

func TestRepositoryFileEnv(t *testing.T) {
	env := initLocalResticRepo(t)
	applyEnv(t, env)

	repoFile := filepath.Join(t.TempDir(), "repository")
	if err := os.WriteFile(repoFile, []byte(os.Getenv("RESTIC_REPOSITORY")+"\n"), 0o600); err != nil {
		t.Fatalf("write repository file failed: %v", err)
	}
	t.Setenv("RESTIC_REPOSITORY", "")
	t.Setenv("RESTIC_REPOSITORY_FILE", repoFile)

	if err := updateResticMetrics(context.Background(), config{}); err != nil {
		t.Fatalf("updateResticMetrics() with RESTIC_REPOSITORY_FILE failed: %v", err)
	}
}

func TestRepositoryEnvMutualExclusion(t *testing.T) {
	env := initLocalResticRepo(t)
	applyEnv(t, env)

	repoFile := filepath.Join(t.TempDir(), "repository")
	if err := os.WriteFile(repoFile, []byte(os.Getenv("RESTIC_REPOSITORY")), 0o600); err != nil {
		t.Fatalf("write repository file failed: %v", err)
	}
	t.Setenv("RESTIC_REPOSITORY_FILE", repoFile)

	repo, err := openRepository(context.Background())
	if repo != nil {
		defer func() { _ = repo.Close() }()
	}
	if err == nil {
		t.Fatal("openRepository() with both RESTIC_REPOSITORY and RESTIC_REPOSITORY_FILE should fail")
	}
}

func TestPasswordCommand(t *testing.T) {
	env := initLocalResticRepo(t)
	applyEnv(t, env)
	t.Setenv("RESTIC_PASSWORD", "")
	t.Setenv("RESTIC_PASSWORD_COMMAND", "echo password")

	if err := updateResticMetrics(context.Background(), config{}); err != nil {
		t.Fatalf("updateResticMetrics() with RESTIC_PASSWORD_COMMAND failed: %v", err)
	}
}

func TestPasswordSourceMutualExclusion(t *testing.T) {
	clearResticEnv(t)
	t.Setenv("RESTIC_PASSWORD_FILE", "some-file")
	t.Setenv("RESTIC_PASSWORD_COMMAND", "some-command")

	if _, err := resolveResticPassword(); err == nil {
		t.Fatal("resolveResticPassword() with both RESTIC_PASSWORD_FILE and RESTIC_PASSWORD_COMMAND should fail")
	}
}

func TestEmptyResolvedPasswordFails(t *testing.T) {
	env := initLocalResticRepo(t)
	applyEnv(t, env)
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write password file failed: %v", err)
	}
	t.Setenv("RESTIC_PASSWORD", "")
	t.Setenv("RESTIC_PASSWORD_FILE", passwordFile)

	repo, err := openRepository(context.Background())
	if repo != nil {
		defer func() { _ = repo.Close() }()
	}
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("openRepository() with a blank password file should fail with an empty-password error, got: %v", err)
	}
}

func labelValue(t *testing.T, name, label string) string {
	t.Helper()
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == label {
					return lp.GetValue()
				}
			}
		}
	}
	return ""
}

func TestOneshotStdoutAndHTTPOutput(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	code := run([]string{"--output", "-"})
	_ = w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	if code != 0 || !strings.Contains(string(out), "restic_snapshots_total") {
		t.Fatalf("stdout output: code=%d, got:\n%s", code, out)
	}

	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	if code := run([]string{"--output", srv.URL}); code != 0 {
		t.Fatalf("HTTP output: run() returned %d", code)
	}
	if !strings.Contains(string(posted), "restic_snapshots_total") {
		t.Fatalf("HTTP output: POST body missing metrics, got:\n%s", posted)
	}
}

func TestSnapshotLabels(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))

	if err := updateResticMetrics(context.Background(), config{IncludePaths: true}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	if _, ok := metricValue(t, "restic_backup_timestamp", map[string]string{"snapshot_tag": "tag1", "snapshot_tags": "tag1,tag2"}); !ok {
		t.Fatal("expected sorted tag labels tag1 / tag1,tag2")
	}
	if got := labelValue(t, "restic_backup_timestamp", "snapshot_paths"); got == "" {
		t.Fatal("expected non-empty snapshot_paths label with IncludePaths")
	}
}

func TestSnapshotWithoutSummary(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))
	ctx := context.Background()

	repo, err := openRepository(ctx)
	if err != nil {
		t.Fatalf("openRepository() failed: %v", err)
	}
	snaps, err := getSnapshots(ctx, repo)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("getSnapshots() = %d snaps, err %v", len(snaps), err)
	}
	sn := &data.Snapshot{Time: time.Now(), Tree: snaps[0].Tree, Paths: snaps[0].Paths, Hostname: "nosummary"}
	if _, err := data.SaveSnapshot(ctx, repo, sn); err != nil {
		t.Fatalf("SaveSnapshot() failed: %v", err)
	}
	_ = repo.Close()

	if err := updateResticMetrics(ctx, config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	got, ok := metricValue(t, "restic_backup_size_total", map[string]string{"client_hostname": "nosummary"})
	if !ok || got != -1 {
		t.Fatalf("restic_backup_size_total = %v (present=%v), want -1 for a snapshot without summary", got, ok)
	}
}

func TestZeroByteLockCounted(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))

	lockFile := filepath.Join(os.Getenv("RESTIC_REPOSITORY"), "locks", strings.Repeat("0", 64))
	if err := os.WriteFile(lockFile, nil, 0o600); err != nil {
		t.Fatalf("write lock file failed: %v", err)
	}
	if err := updateResticMetrics(context.Background(), config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	if got, _ := metricValue(t, "restic_locks_total", nil); got != 1 {
		t.Fatalf("restic_locks_total = %v, want 1 for a zero-byte lock file", got)
	}
	if got, _ := metricValue(t, "restic_stale_locks_total", nil); got != 0 {
		t.Fatalf("restic_stale_locks_total = %v, want 0", got)
	}
}

func TestMetricsHandlerFailsUntilRefreshSucceeds(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))
	if err := updateResticMetrics(context.Background(), config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}

	var refreshErr atomic.Pointer[string]
	failure := "unable to open repository"
	refreshErr.Store(&failure)
	handler := newMetricsHandler(&refreshErr)

	get := func() *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec
	}

	rec := get()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d while the last refresh failed", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), failure) {
		t.Fatalf("body = %q, want the refresh error", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "restic_locks_total") {
		t.Fatalf("failed refresh must not serve metrics, got:\n%s", rec.Body.String())
	}

	refreshErr.Store(nil)
	rec = get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d after a successful refresh", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "restic_locks_total") {
		t.Fatalf("expected metrics after a successful refresh, got:\n%s", rec.Body.String())
	}
}

func TestHealthzIsIndependentOfRefreshState(t *testing.T) {
	var refreshErr atomic.Pointer[string]
	failure := "unable to open repository"
	refreshErr.Store(&failure)
	handler := newHealthzHandler()

	for _, state := range []string{"failed", "succeeded"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d with a %s refresh, want %d", rec.Code, state, http.StatusOK)
		}
		refreshErr.Store(nil)
	}
}

func TestReadyzFailsUntilRefreshSucceeds(t *testing.T) {
	var refreshErr atomic.Pointer[string]
	failure := "unable to open repository"
	refreshErr.Store(&failure)
	handler := newReadyzHandler(&refreshErr)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d while the last refresh failed, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), failure) {
		t.Fatalf("body = %q, want the refresh error", rec.Body.String())
	}

	refreshErr.Store(nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d after a successful refresh, want %d", rec.Code, http.StatusOK)
	}
}

func TestCollectionErrorOnMissingRepo(t *testing.T) {
	clearResticEnv(t)
	t.Setenv("RESTIC_REPOSITORY", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("RESTIC_PASSWORD", "password")

	if err := updateResticMetrics(context.Background(), config{}); err == nil {
		t.Fatal("updateResticMetrics() on a missing repository should fail")
	}
}

func TestCacheDirFallback(t *testing.T) {
	env := initLocalResticRepo(t)
	applyEnv(t, env)
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	t.Setenv("RESTIC_CACHE_DIR", filepath.Join(notADir, "cache"))

	if err := updateResticMetrics(context.Background(), config{}); err != nil {
		t.Fatalf("updateResticMetrics() with an unusable cache dir failed: %v", err)
	}
}

func TestCacheDirUnwritableFallback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions are not enforced for root")
	}
	applyEnv(t, initLocalResticRepo(t))
	readOnlyDir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(readOnlyDir, 0o500); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	t.Setenv("RESTIC_CACHE_DIR", readOnlyDir)

	if err := updateResticMetrics(context.Background(), config{}); err != nil {
		t.Fatalf("updateResticMetrics() with an unwritable cache dir failed: %v", err)
	}
}

func TestOpenRepositorySurfacesResticWarnings(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions are not enforced for root")
	}
	applyEnv(t, initLocalResticRepo(t))
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cacheDir, 0o300); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cacheDir, 0o700) })
	t.Setenv("RESTIC_CACHE_DIR", cacheDir)

	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	repo, err := openRepository(context.Background())
	if err != nil {
		t.Fatalf("openRepository() failed: %v", err)
	}
	defer func() { _ = repo.Close() }()

	if !strings.Contains(buf.String(), "old cache directories") {
		t.Fatalf("expected restic cache warning to reach slog, got: %q", buf.String())
	}
}

func TestLockMetricsOnUnlockedRepo(t *testing.T) {
	applyEnv(t, initLocalResticRepo(t))

	if err := updateResticMetrics(context.Background(), config{}); err != nil {
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
	ctx := context.Background()

	// Stale() SIGHUPs the lock's PID, which is this process
	signal.Ignore(syscall.SIGHUP)
	t.Cleanup(func() { signal.Reset(syscall.SIGHUP) })

	repo, err := openRepository(ctx)
	if err != nil {
		t.Fatalf("openRepository() failed: %v", err)
	}
	defer func() { _ = repo.Close() }()

	unlocker, _, err := repository.Lock(ctx, repo, false, 0, func(string) {}, func(string, ...interface{}) {})
	if err != nil {
		t.Fatalf("failed to lock repository: %v", err)
	}
	defer unlocker.Unlock()

	if err := updateResticMetrics(ctx, config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	if got, _ := metricValue(t, "restic_locks_total", nil); got < 1 {
		t.Fatalf("restic_locks_total = %v, want at least 1", got)
	}
	if got, _ := metricValue(t, "restic_stale_locks_total", nil); got != 0 {
		t.Fatalf("restic_stale_locks_total = %v, want 0 for a freshly held lock", got)
	}

	original := restic.StaleLockTimeout
	restic.StaleLockTimeout = -time.Second
	defer func() { restic.StaleLockTimeout = original }()

	if err := updateResticMetrics(ctx, config{}); err != nil {
		t.Fatalf("updateResticMetrics() failed: %v", err)
	}
	if got, _ := metricValue(t, "restic_stale_locks_total", nil); got < 1 {
		t.Fatalf("restic_stale_locks_total = %v, want at least 1 with a negative timeout", got)
	}
}
