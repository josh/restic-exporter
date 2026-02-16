package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
)

var (
	version      = "0.0.0"
	resticBinary = "restic"
)

type config struct {
	RefreshInterval int
	ListenAddress   string
	ListenPort      int
	NoCheck         bool
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
		NoCheck:         parseBoolEnv("RESTIC_EXPORTER_NO_CHECK", false),
		IncludePaths:    parseBoolEnv("RESTIC_EXPORTER_INCLUDE_PATHS", false),
		Output:          os.Getenv("RESTIC_EXPORTER_OUTPUT"),
	}
}

type snapshotSummaryJSON struct {
	FilesNew            *int64  `json:"files_new"`
	FilesChanged        *int64  `json:"files_changed"`
	FilesUnmodified     *int64  `json:"files_unmodified"`
	DirsNew             *int64  `json:"dirs_new"`
	DirsChanged         *int64  `json:"dirs_changed"`
	DirsUnmodified      *int64  `json:"dirs_unmodified"`
	DataAdded           *int64  `json:"data_added"`
	TotalFilesProcessed *int64  `json:"total_files_processed"`
	TotalBytesProcessed *int64  `json:"total_bytes_processed"`
	TotalDuration       *int64  `json:"total_duration"`
	BackupStart         *string `json:"backup_start"`
	BackupEnd           *string `json:"backup_end"`
}

type snapshotJSON struct {
	ShortID        string               `json:"short_id"`
	ID             string               `json:"id"`
	Hostname       string               `json:"hostname"`
	Username       string               `json:"username"`
	Time           string               `json:"time"`
	Paths          []string             `json:"paths"`
	Tags           []string             `json:"tags"`
	ProgramVersion string               `json:"program_version"`
	Summary        *snapshotSummaryJSON `json:"summary"`
}

type statsJSON struct {
	TotalSize                int64    `json:"total_size"`
	TotalFileCount           int64    `json:"total_file_count"`
	SnapshotsCount           *int64   `json:"snapshots_count"`
	TotalUncompressedSize    *int64   `json:"total_uncompressed_size"`
	CompressionRatio         *float64 `json:"compression_ratio"`
	TotalCiphertextBlobCount *int64   `json:"total_ciphertext_blob_count"`
	TotalBlobCount           *int64   `json:"total_blob_count"`
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

func runRestic(args ...string) ([]byte, error) {
	cmd := exec.Command(resticBinary, args...)
	stdout, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if ok := false; func() bool { exitErr, ok = err.(*exec.ExitError); return ok }() {
			stderr := strings.ReplaceAll(string(exitErr.Stderr), "\n", " ")
			return nil, fmt.Errorf("error executing restic %s: %s exit code: %d", args[0], stderr, exitErr.ExitCode())
		}
		return nil, fmt.Errorf("error executing restic %s: %v", args[0], err)
	}
	return stdout, nil
}

func getSnapshots() ([]snapshotJSON, error) {
	args := []string{"--no-lock", "snapshots", "--json"}
	out, err := runRestic(args...)
	if err != nil {
		return nil, err
	}
	var snaps []snapshotJSON
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("error parsing snapshots JSON: %w", err)
	}
	return snaps, nil
}

func getLatestSnapshots() ([]snapshotJSON, error) {
	args := []string{"--no-lock", "snapshots", "--latest", "1", "--json"}
	out, err := runRestic(args...)
	if err != nil {
		return nil, err
	}
	var snaps []snapshotJSON
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("error parsing latest snapshots JSON: %w", err)
	}
	return snaps, nil
}

func getGlobalStats() (statsJSON, error) {
	args := []string{"--no-lock", "stats", "--json"}
	args = append(args, "--mode", "raw-data")
	out, err := runRestic(args...)
	if err != nil {
		return statsJSON{}, err
	}
	var stats statsJSON
	if err := json.Unmarshal(out, &stats); err != nil {
		return statsJSON{}, fmt.Errorf("error parsing stats JSON: %w", err)
	}
	return stats, nil
}

func getCheck() int {
	args := []string{"--no-lock", "check"}
	_, err := runRestic(args...)
	if err != nil {
		slog.Warn("Error checking the repository health", "error", err)
		return 0
	}
	return 1
}

var lockLineRe = regexp.MustCompile(`^[a-z0-9]+$`)

func getLocks() (int, error) {
	args := []string{"--no-lock", "list", "locks"}
	out, err := runRestic(args...)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if lockLineRe.MatchString(line) {
			count++
		}
	}
	return count, nil
}

func calcSnapshotHash(hostname, username string, paths []string) string {
	normalized := append([]string(nil), paths...)
	sort.Strings(normalized)
	text := hostname + username + strings.Join(normalized, ",")
	h := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", h)
}

func calcSnapshotTimestamp(timeStr string) (float64, error) {
	t, err := time.Parse(time.RFC3339Nano, timeStr)
	if err != nil {
		return 0, err
	}
	return float64(t.Unix()), nil
}

func ptrToFloat(p *int64, fallback float64) float64 {
	if p == nil {
		return fallback
	}
	return float64(*p)
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
	checkSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_check_success",
		Help: "Result of restic check operation in the repository",
	})
	locksTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "restic_locks_total",
		Help: "Total number of locks in the repository",
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
		checkSuccess,
		locksTotal,
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

func updateResticMetrics(cfg config) error {
	start := time.Now()

	allSnaps, err := getSnapshots()
	if err != nil {
		slog.Warn("Failed to get snapshots", "error", err)
		return err
	}

	snapCounter := map[string]int{}
	for _, snap := range allSnaps {
		h := calcSnapshotHash(snap.Hostname, snap.Username, snap.Paths)
		snapCounter[h]++
	}

	latestSnaps, err := getLatestSnapshots()
	if err != nil {
		slog.Warn("Failed to get latest snapshots", "error", err)
		return err
	}

	type snapWithMeta struct {
		snap      snapshotJSON
		hash      string
		timestamp float64
	}
	deduped := map[string]snapWithMeta{}
	for _, snap := range latestSnaps {
		h := calcSnapshotHash(snap.Hostname, snap.Username, snap.Paths)
		ts, err := calcSnapshotTimestamp(snap.Time)
		if err != nil {
			slog.Warn("Failed to parse snapshot time", "time", snap.Time, "error", err)
			continue
		}
		if existing, ok := deduped[h]; !ok || ts > existing.timestamp {
			deduped[h] = snapWithMeta{snap: snap, hash: h, timestamp: ts}
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
			timestamp:     sm.timestamp,
		}

		if snap.Summary != nil {
			c.totalSize = ptrToFloat(snap.Summary.TotalBytesProcessed, -1)
			c.totalFileCount = ptrToFloat(snap.Summary.TotalFilesProcessed, -1)
			c.filesNew = ptrToFloat(snap.Summary.FilesNew, -1)
			c.filesChanged = ptrToFloat(snap.Summary.FilesChanged, -1)
			c.filesUnmodified = ptrToFloat(snap.Summary.FilesUnmodified, -1)
			c.dirsNew = ptrToFloat(snap.Summary.DirsNew, -1)
			c.dirsChanged = ptrToFloat(snap.Summary.DirsChanged, -1)
			c.dirsUnmodified = ptrToFloat(snap.Summary.DirsUnmodified, -1)
			c.dataAdded = ptrToFloat(snap.Summary.DataAdded, -1)

			c.duration = -1
			if snap.Summary.BackupStart != nil && snap.Summary.BackupEnd != nil {
				startT, err1 := time.Parse(time.RFC3339Nano, *snap.Summary.BackupStart)
				endT, err2 := time.Parse(time.RFC3339Nano, *snap.Summary.BackupEnd)
				if err1 == nil && err2 == nil {
					c.duration = endT.Sub(startT).Seconds()
				}
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

	gstats, err := getGlobalStats()
	if err != nil {
		slog.Warn("Failed to get global stats", "error", err)
		return err
	}
	globalSize := float64(gstats.TotalSize)
	globalUncompressedSize := float64(-1)
	if gstats.TotalUncompressedSize != nil {
		globalUncompressedSize = float64(*gstats.TotalUncompressedSize)
	}
	globalCompressionRatio := float64(-1)
	if gstats.CompressionRatio != nil {
		globalCompressionRatio = *gstats.CompressionRatio
	}
	globalBlobCount := float64(-1)
	if gstats.TotalBlobCount != nil {
		globalBlobCount = float64(*gstats.TotalBlobCount)
	}
	globalSnapshotsCount := float64(-1)
	if gstats.SnapshotsCount != nil {
		globalSnapshotsCount = float64(*gstats.SnapshotsCount)
	}

	var checkVal float64
	if !cfg.NoCheck {
		checkVal = float64(getCheck())
	} else {
		checkVal = 2
	}

	lockCount, err := getLocks()
	if err != nil {
		slog.Warn("Failed to get locks", "error", err)
		return err
	}
	locksVal := float64(lockCount)

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

	checkSuccess.Set(checkVal)
	locksTotal.Set(locksVal)
	sizeTotal.Set(globalSize)
	uncompressedSizeTotal.Set(globalUncompressedSize)
	compressionRatio.Set(globalCompressionRatio)
	blobCountTotal.Set(globalBlobCount)
	snapshotsTotal.Set(globalSnapshotsCount)
	scrapeDurationSeconds.Set(time.Since(start).Seconds())

	return nil
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

func writeToStdout(g prometheus.Gatherer) error {
	mfs, err := g.Gather()
	if err != nil {
		return err
	}
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(os.Stdout, mf); err != nil {
			return err
		}
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
	noCheck := flagSet.Bool("no-check", cfg.NoCheck, "Disable repository health checks")
	includePaths := flagSet.Bool("include-paths", cfg.IncludePaths, "Include snapshot paths in labels")
	output := flagSet.String("output", cfg.Output, "Write metrics to file and exit (use - for stdout)")
	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}

	cfg.RefreshInterval = *refreshInterval
	cfg.ListenAddress = *listenAddress
	cfg.ListenPort = *listenPort
	cfg.NoCheck = *noCheck
	cfg.IncludePaths = *includePaths
	cfg.Output = *output

	var level slog.Level
	if *verbose {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	slog.Info("Starting Restic Prometheus Exporter", "version", version)
	slog.Info("It could take a while if the repository is remote")

	if os.Getenv("RESTIC_REPOSITORY") == "" {
		slog.Error("The environment variable RESTIC_REPOSITORY is mandatory")
		return 1
	}

	if os.Getenv("RESTIC_PASSWORD") == "" && os.Getenv("RESTIC_PASSWORD_FILE") == "" && os.Getenv("RESTIC_PASSWORD_COMMAND") == "" {
		slog.Error("One of the environment variables RESTIC_PASSWORD, RESTIC_PASSWORD_FILE or RESTIC_PASSWORD_COMMAND is mandatory")
		return 1
	}

	if cfg.Output != "" {
		if err := updateResticMetrics(cfg); err != nil {
			slog.Error("Failed to collect metrics", "error", err)
			return 1
		}
		if cfg.Output == "-" {
			if err := writeToStdout(registry); err != nil {
				slog.Error("Failed to write metrics to stdout", "error", err)
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

	var ready atomic.Bool
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.RefreshInterval) * time.Second)
		defer ticker.Stop()
		for {
			slog.Info("Refreshing stats", "interval_seconds", cfg.RefreshInterval)
			if err := updateResticMetrics(cfg); err != nil {
				slog.Error("Unable to collect metrics from Restic", "error", err)
			}
			ready.Store(true)
			<-ticker.C
		}
	}()

	metricsHandler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "Collecting initial metrics", http.StatusServiceUnavailable)
			return
		}
		metricsHandler.ServeHTTP(w, r)
	})

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
