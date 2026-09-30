package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	s3store "github.com/xMlex/s3vault/internal/adapter/s3"
	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/httpserver"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/period"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/service"
)

const envPrefix = "S3VAULT"

// defaultVirtualBucket names the bucket the S3 facade advertises when neither
// server.s3_bucket nor s3.bucket is set (local backend).
const defaultVirtualBucket = "s3vault"

// Options are compile-time CLI parameters.
type Options struct {
	Version string
	Stderr  io.Writer
	Stdout  io.Writer
}

type runState struct {
	v      *viper.Viper
	cfg    config.Config
	logger *slog.Logger
}

// NewRootCommand builds the s3vault command tree.
func NewRootCommand(opt Options) *cobra.Command {
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Version == "" {
		opt.Version = "dev"
	}

	state := &runState{v: viper.New()}
	var cfgFile string

	root := &cobra.Command{
		Use:           "s3vault",
		Short:         "Archive files to S3-compatible object storage or a local directory",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := initViper(state.v, cfgFile); err != nil {
				return err
			}
			cfg, err := config.Load(state.v)
			if err != nil {
				return err
			}
			if config.SecretsInPlainConfig(state.v) {
				slog.New(slog.NewJSONHandler(opt.Stderr, nil)).Warn(config.WarnSecrets().Error())
			}
			state.cfg = cfg
			state.logger = newLogger(opt.Stderr, cfg.Log.Level)
			slog.SetDefault(state.logger)
			return nil
		},
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (yaml)")
	root.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	mustBind(root, state.v, "log.level", "log-level")

	root.AddCommand(newArchiveCmd(state))
	root.AddCommand(newUploadCmd(state))
	root.AddCommand(newDownloadCmd(state))
	root.AddCommand(newServerCmd(state))
	root.AddCommand(newCacheCmd(state))
	root.AddCommand(newVersionCmd(opt.Version))
	return root
}

func initViper(v *viper.Viper, cfgFile string) error {
	config.SetDefaults(v)
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	if err := config.BindEnv(v); err != nil {
		return err
	}
	v.AutomaticEnv()

	configPath := cfgFile
	if configPath == "" {
		configPath = findYAMLConfigFile()
	}
	if configPath == "" {
		return nil
	}

	v.SetConfigFile(configPath)
	if err := v.ReadInConfig(); err != nil {
		if cfgFile != "" {
			return fmt.Errorf("reading config %s: %w", configPath, err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "warning: ignoring unreadable config file %s: %v\n", configPath, err)
	}
	return nil
}

// findYAMLConfigFile locates s3vault.yaml or s3vault.yml in standard search paths.
// Viper's SetConfigName also matches a bare "s3vault" file, which would pick up the
// s3vault binary when run from the build directory.
func findYAMLConfigFile() string {
	for _, dir := range configSearchDirs() {
		for _, name := range []string{"s3vault.yaml", "s3vault.yml"} {
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err == nil && !info.IsDir() {
				abs, err := filepath.Abs(path)
				if err == nil {
					return abs
				}
				return path
			}
		}
	}
	return ""
}

func configSearchDirs() []string {
	dirs := []string{"."}
	if dir, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(dir, "s3vault"))
	}
	return dirs
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv}))
}

func mustBind(cmd *cobra.Command, v *viper.Viper, key, flag string) {
	f := cmd.PersistentFlags().Lookup(flag)
	if f == nil {
		f = cmd.Flags().Lookup(flag)
	}
	if err := v.BindPFlag(key, f); err != nil {
		panic(err)
	}
}

func newArchiveCmd(state *runState) *cobra.Command {
	var (
		olderThan     string
		dryRun        bool
		workers       int
		failFast      bool
		output        string
		prefix        string
		bucket        string
		deleteAfter   bool
		deleteIfExist bool
		metricsListen string
	)
	cmd := &cobra.Command{
		Use:   "archive <dir>",
		Short: "Find files older than a period and upload them to the object store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := state.cfg
			if cmd.Flags().Changed("prefix") {
				cfg.S3.Prefix = prefix
			}
			if cmd.Flags().Changed("bucket") {
				cfg.S3.Bucket = bucket
			}
			if olderThan != "" {
				cfg.Archive.OlderThan = olderThan
			}
			if workers > 0 {
				cfg.Archive.Workers = workers
			}
			d, err := period.Parse(cfg.Archive.OlderThan)
			if err != nil {
				return err
			}
			keys := keying.Mapper{Prefix: cfg.KeyPrefix()}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			met, stop, err := startMetrics(metricsListen)
			if err != nil {
				return err
			}
			defer stop()

			svc, closeStore, err := newArchiveService(ctx, state, cfg, keys, dryRun)
			if err != nil {
				return err
			}
			defer closeStore()
			svc = svc.WithMetrics(met)
			st, err := svc.Run(ctx, service.ArchiveOptions{
				Root:              args[0],
				OlderThan:         d,
				DryRun:            dryRun,
				Workers:           cfg.Archive.Workers,
				FailFast:          failFast || cfg.Archive.FailFast,
				DeleteAfterUpload: deleteAfter || cfg.Archive.DeleteAfterUpload,
				DeleteIfExists:    deleteIfExist || cfg.Archive.DeleteIfExists,
			})
			if printErr := printStats(cmd.OutOrStdout(), output, st); printErr != nil {
				return printErr
			}
			if err != nil {
				if errors.Is(err, domain.ErrPartialFailures) {
					return &ExitError{Code: 1, Err: err}
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&olderThan, "older-than", "", "only files with mtime older than this (7d, 24h, 1w)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "scan and print keys without uploading")
	cmd.Flags().IntVar(&workers, "workers", 0, "parallel workers (default from config)")
	cmd.Flags().BoolVar(&failFast, "fail-fast", false, "stop on the first file error")
	cmd.Flags().StringVar(&output, "output", "text", "summary format: text|json")
	cmd.Flags().StringVar(&prefix, "prefix", "", "object key prefix joined with paths under <dir> (e.g. fs.auto-sopd)")
	cmd.Flags().StringVar(&bucket, "bucket", "", "S3 bucket (backend.type=s3 only)")
	cmd.Flags().BoolVar(&deleteAfter, "delete-after-upload", false, "delete local file after a successful upload")
	cmd.Flags().BoolVar(&deleteIfExist, "delete-if-exists", false, "delete local file when remote already has identical content (skip)")
	cmd.Flags().StringVar(&metricsListen, "metrics-listen", "", "prometheus bind address for the duration of the run")
	return cmd
}

func printStats(w io.Writer, format string, st domain.ArchiveStats) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		return enc.Encode(st)
	default:
		_, err := fmt.Fprintf(w, "found=%d uploaded=%d skipped=%d failed=%d bytes_uploaded=%d duration=%s\n",
			st.Found, st.Uploaded, st.Skipped, st.Failed, st.BytesUploaded, st.Duration.Round(time.Millisecond))
		return err
	}
}

func newUploadCmd(state *runState) *cobra.Command {
	var (
		key           string
		root          string
		prefix        string
		bucket        string
		dryRun        bool
		deleteAfter   bool
		deleteIfExist bool
		output        string
		metricsListen string
	)
	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Upload a single file to the object store (same identity and encryption as archive)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := state.cfg
			if cmd.Flags().Changed("prefix") {
				cfg.S3.Prefix = prefix
			}
			if cmd.Flags().Changed("bucket") {
				cfg.S3.Bucket = bucket
			}
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("abs path: %w", err)
			}
			if root == "" {
				root = filepath.Dir(abs)
			}
			scan := scanner.New(scanner.Options{
				FollowSymlinks: cfg.Archive.FollowSymlinks,
				Logger:         state.logger,
			})
			info, err := scan.Stat(root, abs)
			if err != nil {
				return err
			}
			keys := keying.Mapper{Prefix: cfg.KeyPrefix()}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			met, stop, err := startMetrics(metricsListen)
			if err != nil {
				return err
			}
			defer stop()
			svc, closeStore, err := newArchiveService(ctx, state, cfg, keys, dryRun)
			if err != nil {
				return err
			}
			defer closeStore()
			svc = svc.WithMetrics(met)
			st, _, err := svc.UploadFile(ctx, info, service.ArchiveOptions{
				Root:              root,
				DryRun:            dryRun,
				DeleteAfterUpload: deleteAfter || cfg.Archive.DeleteAfterUpload,
				DeleteIfExists:    deleteIfExist || cfg.Archive.DeleteIfExists,
				ExplicitKey:       key,
				Op:                metrics.OpUpload,
			})
			if printErr := printStats(cmd.OutOrStdout(), output, st); printErr != nil {
				return printErr
			}
			return err
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "object key relative to --prefix / s3.prefix (default: filename under --root)")
	cmd.Flags().StringVar(&root, "root", "", "keying root (default: parent directory of the file)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "object key prefix joined with --key or filename (e.g. fs.auto-user-avatars)")
	cmd.Flags().StringVar(&bucket, "bucket", "", "S3 bucket (backend.type=s3 only)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the object key without uploading")
	cmd.Flags().BoolVar(&deleteAfter, "delete-after-upload", false, "delete local file after a successful upload")
	cmd.Flags().BoolVar(&deleteIfExist, "delete-if-exists", false, "delete local file when remote already has identical content (skip)")
	cmd.Flags().StringVar(&output, "output", "text", "summary format: text|json")
	cmd.Flags().StringVar(&metricsListen, "metrics-listen", "", "prometheus bind address for the duration of the run")
	return cmd
}

func newDownloadCmd(state *runState) *cobra.Command {
	var metricsListen string
	cmd := &cobra.Command{
		Use:   "download <object-key> [destination]",
		Short: "Download an object from the object store and decrypt if needed",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dest := "-"
			if len(args) == 2 {
				dest = args[1]
			}
			enc, err := encrypt.New(state.cfg.Encryption)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			store, closeStore, err := newObjectStore(ctx, state.cfg, state.logger)
			if err != nil {
				return err
			}
			defer closeStore()
			met, stop, err := startMetrics(metricsListen)
			if err != nil {
				return err
			}
			defer stop()

			return service.NewFetch(store, enc).WithMetrics(met).WithLogger(state.logger).
				WithRawLayout(rawLocalLayout(state.cfg)).
				Download(ctx, args[0], dest, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&metricsListen, "metrics-listen", "", "prometheus bind address for the duration of the run")
	return cmd
}

func newServerCmd(state *runState) *cobra.Command {
	var listen, metricsListen, s3Listen string
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Serve decrypted objects over HTTP and optional S3 API",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := state.cfg
			if cmd.Flags().Changed("listen") {
				cfg.Server.Listen = listen
			}
			if cmd.Flags().Changed("metrics-listen") {
				cfg.Server.MetricsListen = metricsListen
			}
			if cmd.Flags().Changed("s3-listen") {
				cfg.Server.S3Listen = s3Listen
			}
			enc, err := encrypt.New(cfg.Encryption)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			store, closeStore, err := newObjectStore(ctx, cfg, state.logger)
			if err != nil {
				return err
			}
			defer closeStore()

			reg := prometheus.NewRegistry()
			if err := metrics.RegisterRuntime(reg); err != nil {
				return err
			}
			met, err := metrics.New(reg)
			if err != nil {
				return err
			}

			encFP := encrypt.Fingerprint(cfg.Encryption)
			fetch := service.NewFetch(store, enc).WithMetrics(met).WithLogger(state.logger).
				WithRawLayout(rawLocalLayout(cfg))
			var disk port.PlaintextCache
			if cfg.Cache.Enabled {
				d, err := cache.New(cache.Options{
					Dir:      cfg.Cache.Dir,
					TTL:      cfg.Cache.TTL,
					MaxBytes: cfg.Cache.MaxBytes,
				})
				if err != nil {
					return err
				}
				defer d.Close()
				d.StartSweeper(ctx, cfg.Cache.SweepInterval, state.logger)
				if err := met.RegisterCacheUsage(func() (int, int64, error) {
					st, err := d.Usage()
					return st.Entries, st.Bytes, err
				}); err != nil {
					return err
				}
				fetch = fetch.WithCache(d, cfg.CacheNamespace(), encFP).WithSoftTTL(cfg.Cache.SoftTTL)
				disk = d
				state.logger.Info("plaintext cache enabled", "op", "cache", "dir", d.Dir())
			} else {
				state.logger.Info("plaintext cache disabled", "op", "cache")
			}
			keys := keying.Mapper{Prefix: cfg.KeyPrefix()}
			scan := scanner.New(scanner.Options{
				FollowSymlinks: cfg.Archive.FollowSymlinks,
				Logger:         state.logger,
			})
			arch := service.NewArchive(scan, keys, store, enc, state.logger).WithMetrics(met)

			var s3Handler http.Handler
			if cfg.Server.S3APIEnabled() {
				virtBucket := cfg.Server.S3Bucket
				if virtBucket == "" {
					// A local backend has no bucket of its own.
					virtBucket = cfg.S3.Bucket
				}
				if virtBucket == "" {
					virtBucket = defaultVirtualBucket
				}
				region := cfg.Server.S3Region
				if region == "" {
					region = cfg.S3.Region
				}
				idBucket := virtBucket
				if cfg.Server.S3BucketAsPrefix {
					idBucket = "" // Allow any client bucket; name becomes key prefix
				}
				id := &s3auth.Static{
					AccessKey: cfg.Server.S3AccessKey,
					SecretKey: cfg.Server.S3SecretKey,
					Bucket:    idBucket,
				}
				api, err := s3api.New(s3api.Config{
					Identity:       id,
					Region:         region,
					Bucket:         virtBucket,
					Fetch:          fetch,
					Archive:        arch,
					Keys:           keys,
					Store:          store,
					Cache:          disk,
					BucketBackend:  cfg.CacheNamespace(),
					BucketAsPrefix: cfg.Server.S3BucketAsPrefix,
					EncFP:          encFP,
					Logger:         state.logger,
					Metrics:        met,
				})
				if err != nil {
					return err
				}
				s3Handler = api.Handler()
			}

			srv, err := httpserver.New(httpserver.Config{
				Listen:        cfg.Server.Listen,
				MetricsListen: cfg.Server.MetricsListen,
				S3Listen:      cfg.Server.S3Listen,
				Logger:        state.logger,
				Store:         store,
				Metrics:       met,
				S3Handler:     s3Handler,
			})
			if err != nil {
				return err
			}
			s3Addr := cfg.Server.S3Listen
			if s3Handler != nil && s3Addr == "" {
				s3Addr = cfg.Server.Listen + " (multiplex)"
			}
			if s3Handler == nil {
				s3Addr = "off"
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "listening http=%s s3=%s metrics=%s backend=%s\n",
				cfg.Server.Listen, s3Addr, cfg.Server.MetricsListen, cfg.Backend.Type)
			return srv.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "bind address (default 127.0.0.1:8080)")
	cmd.Flags().StringVar(&metricsListen, "metrics-listen", "", "prometheus bind address")
	cmd.Flags().StringVar(&s3Listen, "s3-listen", "", "S3 API bind (empty=multiplex on --listen when S3 keys set)")
	return cmd
}

func newCacheCmd(state *runState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect or clear the local plaintext cache",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "stats",
		Short: "Show cache usage",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			disk, err := openCache(state.cfg)
			if err != nil {
				return err
			}
			defer disk.Close()
			st, err := disk.Usage()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "entries=%d bytes=%d dir=%s\n", st.Entries, st.Bytes, disk.Dir())
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Delete cached plaintext files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			disk, err := openCache(state.cfg)
			if err != nil {
				return err
			}
			defer disk.Close()
			if err := disk.Clear(); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "cache cleared")
			return err
		},
	})
	return cmd
}

func openCache(cfg config.Config) (*cache.Disk, error) {
	return cache.New(cache.Options{
		Dir:      cfg.Cache.Dir,
		TTL:      cfg.Cache.TTL,
		MaxBytes: cfg.Cache.MaxBytes,
	})
}

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	}
}

func startMetrics(listen string) (*metrics.Collector, func(), error) {
	m, err := metrics.New(nil)
	if err != nil {
		return nil, nil, err
	}
	srv, err := metrics.Listen(listen, m.Gatherer())
	if err != nil {
		return nil, nil, err
	}
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metrics.Shutdown(ctx, srv)
	}
	return m, stop, nil
}

// rawLocalLayout reports whether the local backend stores bare payloads without
// the S3VCTR01 container, so containerless reads are expected rather than anomalous.
func rawLocalLayout(cfg config.Config) bool {
	return cfg.Backend.Type == config.BackendLocal && cfg.Backend.Local.Layout == config.LocalLayoutRaw
}

// newObjectStore builds the backend selected by backend.type and logs where
// objects live. The returned closer releases backend resources and is always
// safe to call.
func newObjectStore(ctx context.Context, cfg config.Config, log *slog.Logger) (port.ObjectStore, func(), error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Backend.Type == config.BackendLocal {
		store, err := localstore.New(cfg.Backend.Local)
		if err != nil {
			return nil, nil, err
		}
		log.Info("object store ready", "op", "backend", "backend", config.BackendLocal,
			"dir", store.Dir(), "layout", store.Layout(), "prefix", cfg.KeyPrefix())
		return store, func() { _ = store.Close() }, nil
	}
	store, err := s3store.New(ctx, cfg.S3)
	if err != nil {
		return nil, nil, err
	}
	log.Info("object store ready", "op", "backend", "backend", config.BackendS3,
		"bucket", cfg.S3.Bucket, "endpoint", cfg.S3.Endpoint, "prefix", cfg.KeyPrefix())
	return store, func() {}, nil
}

// newArchiveService builds archive/upload with a local backend store plus
// encryptor. The returned closer releases the store.
func newArchiveService(ctx context.Context, state *runState, cfg config.Config, keys keying.Mapper, dryRun bool) (*service.Archive, func(), error) {
	noop := func() {}
	scan := scanner.New(scanner.Options{
		FollowSymlinks: cfg.Archive.FollowSymlinks,
		Logger:         state.logger,
	})

	enc, err := encrypt.New(cfg.Encryption)
	if err != nil {
		return nil, nil, err
	}
	if dryRun {
		return service.NewArchive(scan, keys, nil, enc, state.logger), noop, nil
	}
	store, closeStore, err := newObjectStore(ctx, cfg, state.logger)
	if err != nil {
		return nil, nil, err
	}
	return service.NewArchive(scan, keys, store, enc, state.logger), closeStore, nil
}
