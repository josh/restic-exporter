package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/josh/restic-api/api/backend"
	"github.com/josh/restic-api/api/backend/all"
	"github.com/josh/restic-api/api/backend/cache"
	"github.com/josh/restic-api/api/crypto"
	"github.com/josh/restic-api/api/data"
	"github.com/josh/restic-api/api/global"
	"github.com/josh/restic-api/api/repository"
	"github.com/josh/restic-api/api/restic"
	"github.com/josh/restic-api/api/ui"
	"github.com/josh/restic-api/api/ui/progress"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
)

var version = "2.0.1"

type config struct {
	RefreshInterval int
	ListenAddress   string
	ListenPort      int
	IncludePaths    bool
	Output          string
}

func parseBoolEnv(name string, defaultVal bool) bool {
	val, ok := os.LookupEnv(name)
	if !ok {
		return defaultVal
	}
	switch strings.TrimSpace(strings.ToLower(val)) {
	case "false", "f", "0", "":
		return false
	default:
		return true
	}
}

func loadConfig() config {
	refreshInterval := 3600
	if v := os.Getenv("RESTIC_EXPORTER_REFRESH_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			refreshInterval = n
		}
	}

	listenPort := 9183
	if v := os.Getenv("RESTIC_EXPORTER_LISTEN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			listenPort = n
		}
	}

	listenAddress := "[::]"
	if v := os.Getenv("RESTIC_EXPORTER_LISTEN_ADDRESS"); v != "" {
		listenAddress = v
	}

	return config{
		RefreshInterval: refreshInterval,
		ListenAddress:   listenAddress,
		ListenPort:      listenPort,
		IncludePaths:    parseBoolEnv("RESTIC_EXPORTER_INCLUDE_PATHS", false),
		Output:          os.Getenv("RESTIC_EXPORTER_OUTPUT"),
	}
}

type resticClient struct {
	hostname        string
	username        string
	version         string
	hash            string
	tags            string
	tag             string
	paths           string
	snapshotCount   int
	timestamp       float64
	totalSize       float64
	totalFileCount  float64
	filesNew        float64
	filesChanged    float64
	filesUnmodified float64
	dirsNew         float64
	dirsChanged     float64
	dirsUnmodified  float64
	dataAdded       float64
	duration        float64
}

func resolveResticPassword() (string, error) {
	passwordFile := os.Getenv("RESTIC_PASSWORD_FILE")
	passwordCommand := os.Getenv("RESTIC_PASSWORD_COMMAND")
	if passwordFile != "" && passwordCommand != "" {
		return "", errors.New("RESTIC_PASSWORD_FILE and RESTIC_PASSWORD_COMMAND are mutually exclusive")
	}
	if passwordCommand != "" {
		args, err := backend.SplitShellStrings(passwordCommand)
		if err != nil {
			return "", err
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stderr = os.Stderr
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("error executing password command: %w", err)
		}
		return strings.TrimSpace(string(output)), nil
	}
	if passwordFile != "" {
		return global.LoadPasswordFromFile(passwordFile)
	}
	return os.Getenv("RESTIC_PASSWORD"), nil
}

type noTerminal struct{ ui.MockTerminal }

func (*noTerminal) InputIsTerminal() bool { return false }
func (*noTerminal) ReadPassword(context.Context, string) (string, error) {
	return "", errors.New("password prompt is not available")
}

type slogPrinter struct{ progress.NoopPrinter }

func (slogPrinter) E(msg string, args ...interface{}) { slog.Warn(fmt.Sprintf(msg, args...)) }

// OpenRepository hard-fails on cache errors; probe first so we can fall back to NoCache.
func checkCacheDir(dir string) error {
	if dir == "" {
		var err error
		dir, err = cache.DefaultDir()
		if err != nil {
			return err
		}
	}
	return os.MkdirAll(dir, 0o700)
}

func openRepository(ctx context.Context) (*repository.Repository, error) {
	password, err := resolveResticPassword()
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("resolved password is empty; set RESTIC_PASSWORD, RESTIC_PASSWORD_FILE or RESTIC_PASSWORD_COMMAND")
	}
	gopts := global.Options{
		Repo:           os.Getenv("RESTIC_REPOSITORY"),
		RepositoryFile: os.Getenv("RESTIC_REPOSITORY_FILE"),
		KeyHint:        os.Getenv("RESTIC_KEY_HINT"),
		CacheDir:       os.Getenv("RESTIC_CACHE_DIR"),
		NoLock:         true,
		Password:       password,
		Term:           &noTerminal{},
		Backends:       all.Backends(),
	}
	if err := checkCacheDir(gopts.CacheDir); err != nil {
		slog.Warn("Unable to open cache, running without a local cache", "error", err)
		gopts.NoCache = true
	}
	if v := os.Getenv("RESTIC_CACERT"); v != "" {
		gopts.RootCertFilenames = strings.Split(v, ",")
	}
	gopts.TLSClientCertKeyFilename = os.Getenv("RESTIC_TLS_CLIENT_CERT")
	gopts.HTTPUserAgent = os.Getenv("RESTIC_HTTP_USER_AGENT")
	return global.OpenRepository(ctx, gopts, &slogPrinter{})
}

func getSnapshots(ctx context.Context, repo *repository.Repository) ([]*data.Snapshot, error) {
	var snaps []*data.Snapshot
	err := data.ForAllSnapshots(ctx, repo, repo, nil, func(id restic.ID, sn *data.Snapshot, err error) error {
		if err != nil {
			slog.Warn("Failed to load snapshot", "id", id.Str(), "error", err)
			return nil
		}
		snaps = append(snaps, sn)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error listing snapshots: %w", err)
	}
	return snaps, nil
}

type globalStats struct {
	totalSize        float64
	uncompressedSize float64
	compressionRatio float64
	blobCount        float64
	snapshotsCount   float64
}

// Port of `restic stats --mode raw-data` over all snapshots, from
// cmd/restic/cmd_stats.go which is not importable from restic-api.
func getGlobalStats(ctx context.Context, repo *repository.Repository, snaps []*data.Snapshot) (globalStats, error) {
	if err := repo.LoadIndex(ctx, nil); err != nil {
		return globalStats{}, fmt.Errorf("error loading index: %w", err)
	}

	blobs := repo.NewAssociatedBlobSet()
	for _, sn := range snaps {
		if sn.Tree == nil {
			return globalStats{}, fmt.Errorf("snapshot %s has nil tree", sn.ID().Str())
		}
		if err := data.FindUsedBlobs(ctx, repo, restic.IDs{*sn.Tree}, blobs, nil); err != nil {
			// snapshot may have been pruned since the listing
			slog.Warn("Failed to walk snapshot, skipping", "id", sn.ID().Str(), "error", err)
			continue
		}
	}

	var totalSize, totalUncompressed, compressedSize, compressedUncompressed, blobCount uint64
	repoVersion := repo.Config().Version
	for bh := range blobs.Keys() {
		pbs := repo.LookupBlob(bh.Type, bh.ID)
		if len(pbs) == 0 {
			slog.Warn("Blob not found in index, skipping", "blob", bh)
			continue
		}
		pb := pbs[0]
		totalSize += uint64(pb.Length)
		if repoVersion >= 2 {
			totalUncompressed += uint64(crypto.CiphertextLength(int(pb.DataLength())))
			if pb.IsCompressed() {
				compressedSize += uint64(pb.Length)
				compressedUncompressed += uint64(crypto.CiphertextLength(int(pb.DataLength())))
			}
		}
		blobCount++
	}

	gs := globalStats{
		totalSize:        float64(totalSize),
		uncompressedSize: -1,
		compressionRatio: -1,
		blobCount:        -1,
		snapshotsCount:   float64(len(snaps)),
	}
	if totalUncompressed > 0 {
		gs.uncompressedSize = float64(totalUncompressed)
	}
	if compressedSize > 0 {
		gs.compressionRatio = float64(compressedUncompressed) / float64(compressedSize)
	}
	if blobCount > 0 {
		gs.blobCount = float64(blobCount)
	}
	return gs, nil
}

func getLocks(ctx context.Context, repo *repository.Repository) (total, stale int, err error) {
	err = repo.List(ctx, restic.LockFile, func(id restic.ID, size int64) error {
		total++
		if size == 0 {
			// interrupted-upload artifact
			return nil
		}
		lock, err := restic.LoadLock(ctx, repo, id)
		if err != nil {
			slog.Debug("Failed to read lock", "lock", id.Str(), "error", err)
			return nil
		}
		if lock.Stale() {
			stale++
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("error listing locks: %w", err)
	}
	return total, stale, nil
}

func calcSnapshotHash(hostname, username string, paths []string) string {
	normalized := append([]string(nil), paths...)
	sort.Strings(normalized)
	text := hostname + username + strings.Join(normalized, ",")
	h := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", h)
}

var registry = prometheus.NewRegistry()

var commonLabels = []string{
	"client_hostname",
	"client_username",
	"client_version",
	"snapshot_hash",
	"snapshot_tag",
	"snapshot_tags",
	"snapshot_paths",
}

var (
	locksTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_locks_total",
		Help: "Total number of locks in the repository",
	})
	staleLocksTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_stale_locks_total",
		Help: "Total number of locks in the repository considered stale by restic",
	})
	scrapeDurationSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_scrape_duration_seconds",
		Help: "Amount of time each scrape takes",
	})
	sizeTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_size_total",
		Help: "Total size of the repository in bytes",
	})
	uncompressedSizeTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_uncompressed_size_total",
		Help: "Total uncompressed size of the repository in bytes",
	})
	compressionRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_compression_ratio",
		Help: "Compression ratio of the repository",
	})
	blobCountTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_blob_count_total",
		Help: "Total number of blobs in the repository",
	})
	snapshotsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_snapshots_total",
		Help: "Total number of snapshots in the repository",
	})
)

var (
	backupTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_timestamp",
		Help: "Timestamp of the last backup",
	}, commonLabels)
	backupSnapshotsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_snapshots_total",
		Help: "Total number of snapshots",
	}, commonLabels)
	backupFilesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_files_total",
		Help: "Number of files in the backup",
	}, commonLabels)
	backupSizeTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_size_total",
		Help: "Total size of backup in bytes",
	}, commonLabels)
	backupFilesNew = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_files_new",
		Help: "Number of new files in the backup",
	}, commonLabels)
	backupFilesChanged = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_files_changed",
		Help: "Number of changed files in the backup",
	}, commonLabels)
	backupFilesUnmodified = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_files_unmodified",
		Help: "Number of unmodified files in the backup",
	}, commonLabels)
	backupDirsNew = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_dirs_new",
		Help: "Number of new directories in the backup",
	}, commonLabels)
	backupDirsChanged = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_dirs_changed",
		Help: "Number of changed directories in the backup",
	}, commonLabels)
	backupDirsUnmodified = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_dirs_unmodified",
		Help: "Number of unmodified directories in the backup",
	}, commonLabels)
	backupDataAddedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_data_added_bytes",
		Help: "Number of bytes added in the backup",
	}, commonLabels)
	backupDurationSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "restic_backup_duration_seconds",
		Help: "Amount of time Restic took to make the backup",
	}, commonLabels)
)

func init() {
	registry.MustRegister(
		locksTotal,
		staleLocksTotal,
		scrapeDurationSeconds,
		sizeTotal,
		uncompressedSizeTotal,
		compressionRatio,
		blobCountTotal,
		snapshotsTotal,
		backupTimestamp,
		backupSnapshotsTotal,
		backupFilesTotal,
		backupSizeTotal,
		backupFilesNew,
		backupFilesChanged,
		backupFilesUnmodified,
		backupDirsNew,
		backupDirsChanged,
		backupDirsUnmodified,
		backupDataAddedBytes,
		backupDurationSeconds,
	)
}

func updateResticMetrics(ctx context.Context, cfg config) error {
	start := time.Now()

	repo, err := openRepository(ctx)
	if err != nil {
		slog.Warn("Failed to open repository", "error", err)
		return err
	}
	defer func() { _ = repo.Close() }()

	allSnaps, err := getSnapshots(ctx, repo)
	if err != nil {
		slog.Warn("Failed to get snapshots", "error", err)
		return err
	}

	snapCounter := map[string]int{}
	for _, snap := range allSnaps {
		h := calcSnapshotHash(snap.Hostname, snap.Username, snap.Paths)
		snapCounter[h]++
	}

	type snapWithMeta struct {
		snap *data.Snapshot
		hash string
	}
	deduped := map[string]snapWithMeta{}
	for _, snap := range allSnaps {
		h := calcSnapshotHash(snap.Hostname, snap.Username, snap.Paths)
		if existing, ok := deduped[h]; !ok || snap.Time.After(existing.snap.Time) ||
			(snap.Time.Equal(existing.snap.Time) && snap.ID().String() > existing.snap.ID().String()) {
			deduped[h] = snapWithMeta{snap: snap, hash: h}
		}
	}

	hashes := make([]string, 0, len(deduped))
	for h := range deduped {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	var clients []resticClient
	for _, h := range hashes {
		sm := deduped[h]
		snap := sm.snap
		paths := append([]string(nil), snap.Paths...)
		sort.Strings(paths)
		tagsList := append([]string(nil), snap.Tags...)
		sort.Strings(tagsList)

		tag := ""
		if len(tagsList) > 0 {
			tag = tagsList[0]
		}
		tags := strings.Join(tagsList, ",")
		pathsLabel := ""
		if cfg.IncludePaths {
			pathsLabel = strings.Join(paths, ",")
		}

		c := resticClient{
			hostname:      snap.Hostname,
			username:      snap.Username,
			version:       snap.ProgramVersion,
			hash:          h,
			tag:           tag,
			tags:          tags,
			paths:         pathsLabel,
			snapshotCount: snapCounter[h],
			timestamp:     float64(snap.Time.Unix()),
		}

		if snap.Summary != nil {
			c.totalSize = float64(snap.Summary.TotalBytesProcessed)
			c.totalFileCount = float64(snap.Summary.TotalFilesProcessed)
			c.filesNew = float64(snap.Summary.FilesNew)
			c.filesChanged = float64(snap.Summary.FilesChanged)
			c.filesUnmodified = float64(snap.Summary.FilesUnmodified)
			c.dirsNew = float64(snap.Summary.DirsNew)
			c.dirsChanged = float64(snap.Summary.DirsChanged)
			c.dirsUnmodified = float64(snap.Summary.DirsUnmodified)
			c.dataAdded = float64(snap.Summary.DataAdded)

			c.duration = -1
			if !snap.Summary.BackupStart.IsZero() && !snap.Summary.BackupEnd.IsZero() {
				c.duration = snap.Summary.BackupEnd.Sub(snap.Summary.BackupStart).Seconds()
			}
		} else {
			c.totalSize = -1
			c.totalFileCount = -1
			c.filesNew = -1
			c.filesChanged = -1
			c.filesUnmodified = -1
			c.dirsNew = -1
			c.dirsChanged = -1
			c.dirsUnmodified = -1
			c.dataAdded = -1
			c.duration = -1
		}

		clients = append(clients, c)
	}

	gstats, err := getGlobalStats(ctx, repo, allSnaps)
	if err != nil {
		slog.Warn("Failed to get global stats", "error", err)
		return err
	}

	totalLocks, staleLocks, err := getLocks(ctx, repo)
	if err != nil {
		slog.Warn("Failed to get locks", "error", err)
		return err
	}

	backupTimestamp.Reset()
	backupSnapshotsTotal.Reset()
	backupFilesTotal.Reset()
	backupSizeTotal.Reset()
	backupFilesNew.Reset()
	backupFilesChanged.Reset()
	backupFilesUnmodified.Reset()
	backupDirsNew.Reset()
	backupDirsChanged.Reset()
	backupDirsUnmodified.Reset()
	backupDataAddedBytes.Reset()
	backupDurationSeconds.Reset()

	for _, c := range clients {
		labels := prometheus.Labels{
			"client_hostname": c.hostname,
			"client_username": c.username,
			"client_version":  c.version,
			"snapshot_hash":   c.hash,
			"snapshot_tag":    c.tag,
			"snapshot_tags":   c.tags,
			"snapshot_paths":  c.paths,
		}
		backupTimestamp.With(labels).Set(c.timestamp)
		backupSnapshotsTotal.With(labels).Set(float64(c.snapshotCount))
		backupFilesTotal.With(labels).Set(c.totalFileCount)
		backupSizeTotal.With(labels).Set(c.totalSize)
		backupFilesNew.With(labels).Set(c.filesNew)
		backupFilesChanged.With(labels).Set(c.filesChanged)
		backupFilesUnmodified.With(labels).Set(c.filesUnmodified)
		backupDirsNew.With(labels).Set(c.dirsNew)
		backupDirsChanged.With(labels).Set(c.dirsChanged)
		backupDirsUnmodified.With(labels).Set(c.dirsUnmodified)
		backupDataAddedBytes.With(labels).Set(c.dataAdded)
		backupDurationSeconds.With(labels).Set(c.duration)
	}

	locksTotal.Set(float64(totalLocks))
	staleLocksTotal.Set(float64(staleLocks))
	sizeTotal.Set(gstats.totalSize)
	uncompressedSizeTotal.Set(gstats.uncompressedSize)
	compressionRatio.Set(gstats.compressionRatio)
	blobCountTotal.Set(gstats.blobCount)
	snapshotsTotal.Set(gstats.snapshotsCount)
	scrapeDurationSeconds.Set(time.Since(start).Seconds())

	return nil
}

func newHealthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
}

func newReadyzHandler(refreshErr *atomic.Pointer[string]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if msg := refreshErr.Load(); msg != nil {
			http.Error(w, *msg, http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
}

func newMetricsHandler(refreshErr *atomic.Pointer[string]) http.Handler {
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if msg := refreshErr.Load(); msg != nil {
			http.Error(w, *msg, http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func activationListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != fmt.Sprintf("%d", os.Getpid()) {
		return nil, fmt.Errorf("expected LISTEN_PID=%d, but was %s", os.Getpid(), os.Getenv("LISTEN_PID"))
	}
	if os.Getenv("LISTEN_FDS") != "1" {
		return nil, fmt.Errorf("expected LISTEN_FDS=1, but was %s", os.Getenv("LISTEN_FDS"))
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != 1 {
		return nil, fmt.Errorf("expected LISTEN_FDNAMES to set 1 name, but was '%s'", os.Getenv("LISTEN_FDNAMES"))
	}
	fd := 3
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), names[0])
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close file: %w", err)
	}
	return ln, nil
}

func writeMetricsTo(w io.Writer, g prometheus.Gatherer) error {
	mfs, err := g.Gather()
	if err != nil {
		return err
	}
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(w, mf); err != nil {
			return err
		}
	}
	return nil
}

func writeToStdout(g prometheus.Gatherer) error {
	return writeMetricsTo(os.Stdout, g)
}

func isHTTPOutput(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func postMetrics(destURL string, body []byte) error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, destURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", string(expfmt.FmtText))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func run(args []string) int {
	cfg := loadConfig()

	flagSet := flag.NewFlagSet("restic-exporter", flag.ContinueOnError)
	verbose := flagSet.Bool("verbose", false, "Enable debug logging")
	showVersion := flagSet.Bool("version", false, "Print version and exit")
	refreshInterval := flagSet.Int("refresh-interval", cfg.RefreshInterval, "Seconds between metric refreshes")
	listenAddress := flagSet.String("listen-address", cfg.ListenAddress, "Address to listen on")
	listenPort := flagSet.Int("listen-port", cfg.ListenPort, "Port to listen on")
	includePaths := flagSet.Bool("include-paths", cfg.IncludePaths, "Include snapshot paths in labels")
	output := flagSet.String("output", cfg.Output, "Write metrics to file and exit (use - for stdout), or POST to an HTTP(S) URL (e.g. Prometheus push/import endpoint)")
	if err := flagSet.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}

	cfg.RefreshInterval = *refreshInterval
	cfg.ListenAddress = *listenAddress
	cfg.ListenPort = *listenPort
	cfg.IncludePaths = *includePaths
	cfg.Output = *output

	var level slog.Level
	if *verbose {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("Starting Restic Prometheus Exporter", "version", version)

	if os.Getenv("RESTIC_REPOSITORY") == "" && os.Getenv("RESTIC_REPOSITORY_FILE") == "" {
		slog.Error("One of the environment variables RESTIC_REPOSITORY or RESTIC_REPOSITORY_FILE is mandatory")
		return 1
	}

	if os.Getenv("RESTIC_PASSWORD") == "" && os.Getenv("RESTIC_PASSWORD_FILE") == "" && os.Getenv("RESTIC_PASSWORD_COMMAND") == "" {
		slog.Error("One of the environment variables RESTIC_PASSWORD, RESTIC_PASSWORD_FILE or RESTIC_PASSWORD_COMMAND is mandatory")
		return 1
	}

	// api/restic's init swallows SIGHUP; restore the default disposition
	signal.Reset(syscall.SIGHUP)

	slog.Info("Using restic version", "version", global.Version)

	ctx := context.Background()

	if cfg.Output != "" {
		if err := updateResticMetrics(ctx, cfg); err != nil {
			slog.Error("Failed to collect metrics", "error", err)
			return 1
		}
		if cfg.Output == "-" {
			if err := writeToStdout(registry); err != nil {
				slog.Error("Failed to write metrics to stdout", "error", err)
				return 1
			}
		} else if isHTTPOutput(cfg.Output) {
			var buf bytes.Buffer
			if err := writeMetricsTo(&buf, registry); err != nil {
				slog.Error("Failed to serialize metrics", "error", err)
				return 1
			}
			if err := postMetrics(cfg.Output, buf.Bytes()); err != nil {
				slog.Error("Failed to POST metrics", "url", cfg.Output, "error", err)
				return 1
			}
		} else {
			if err := prometheus.WriteToTextfile(cfg.Output, registry); err != nil {
				slog.Error("Failed to write metrics to file", "path", cfg.Output, "error", err)
				return 1
			}
		}
		return 0
	}

	if cfg.RefreshInterval <= 0 || int64(cfg.RefreshInterval) > math.MaxInt64/int64(time.Second) {
		slog.Error("Refresh interval must be positive and fit in a time duration", "refresh_interval", cfg.RefreshInterval)
		return 1
	}

	var refreshErr atomic.Pointer[string]
	initial := "Collecting initial metrics"
	refreshErr.Store(&initial)

	go func() {
		ticker := time.NewTicker(time.Duration(cfg.RefreshInterval) * time.Second)
		defer ticker.Stop()
		for {
			slog.Info("Refreshing stats", "interval_seconds", cfg.RefreshInterval)
			if err := updateResticMetrics(ctx, cfg); err != nil {
				slog.Error("Unable to collect metrics from Restic", "error", err)
				msg := err.Error()
				refreshErr.Store(&msg)
			} else {
				refreshErr.Store(nil)
			}
			<-ticker.C
		}
	}()

	http.Handle("/metrics", newMetricsHandler(&refreshErr))
	http.Handle("/healthz", newHealthzHandler())
	http.Handle("/readyz", newReadyzHandler(&refreshErr))

	var ln net.Listener
	var err error
	if os.Getenv("LISTEN_FDS") == "1" {
		ln, err = activationListener()
	} else {
		addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.ListenPort)
		slog.Info("Serving metrics", "address", "http://"+addr+"/metrics")
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		slog.Error("Listen error", "error", err)
		return 1
	}
	defer func() { _ = ln.Close() }()

	slog.Error("HTTP server error", "error", http.Serve(ln, nil))
	return 1
}

func main() {
	os.Exit(run(os.Args[1:]))
}
