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
	"github.com/xMlex/s3vault/internal/adapter/remote"
	"github.com/xMlex/s3vault/internal/adapter/s3"
	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/httpserver"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/period"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/service"
)

const envPrefix = "S3VAULT"

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
		Short:         "Archive files to S3-compatible object storage",
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
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.AddConfigPath(".")
		if dir, err := os.UserConfigDir(); err == nil {
			v.AddConfigPath(dir + "/s3vault")
		}
		v.SetConfigName("s3vault")
		v.SetConfigType("yaml")
	}
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	if err := config.BindEnv(v); err != nil {
		return err
	}
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("reading config: %w", err)
		}
	}
	return nil
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
		Short: "Find files older than a period and upload them to S3",
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
			keys := keying.Mapper{Prefix: cfg.S3.Prefix}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			onChange, ok := identity.ParseOnChange(cfg.Archive.OnChange)
			if !ok {
				return fmt.Errorf("invalid archive.on_change %q", cfg.Archive.OnChange)
			}
			met, stop, err := startMetrics(metricsListen)
			if err != nil {
				return err
			}
			defer stop()

			svc, err := newArchiveService(ctx, state, cfg, keys, dryRun)
			if err != nil {
				return err
			}
			svc = svc.WithMetrics(met)
			st, err := svc.Run(ctx, service.ArchiveOptions{
				Root:              args[0],
				OlderThan:         d,
				DryRun:            dryRun,
				Workers:           cfg.Archive.Workers,
				FailFast:          failFast || cfg.Archive.FailFast,
				OnChange:          onChange,
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
	cmd.Flags().StringVar(&prefix, "prefix", "", "S3 key prefix joined with paths under <dir> (e.g. fs.auto-sopd)")
	cmd.Flags().StringVar(&bucket, "bucket", "", "S3 bucket")
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
		Short: "Upload a single file to S3 (same identity and encryption as archive)",
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
			keys := keying.Mapper{Prefix: cfg.S3.Prefix}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			onChange, ok := identity.ParseOnChange(cfg.Archive.OnChange)
			if !ok {
				return fmt.Errorf("invalid archive.on_change %q", cfg.Archive.OnChange)
			}
			met, stop, err := startMetrics(metricsListen)
			if err != nil {
				return err
			}
			defer stop()
			svc, err := newArchiveService(ctx, state, cfg, keys, dryRun)
			if err != nil {
				return err
			}
			svc = svc.WithMetrics(met)
			st, _, err := svc.UploadFile(ctx, info, service.ArchiveOptions{
				Root:              root,
				DryRun:            dryRun,
				OnChange:          onChange,
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
	cmd.Flags().StringVar(&prefix, "prefix", "", "S3 key prefix joined with --key or filename (e.g. fs.auto-user-avatars)")
	cmd.Flags().StringVar(&bucket, "bucket", "", "S3 bucket")
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
		Short: "Download an object from S3 and decrypt if needed",
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
			store, err := s3store.New(ctx, state.cfg.S3)
			if err != nil {
				return err
			}
			met, stop, err := startMetrics(metricsListen)
			if err != nil {
				return err
			}
			defer stop()
			return service.NewFetch(store, enc).WithMetrics(met).Download(ctx, args[0], dest, cmd.OutOrStdout())
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
			store, err := s3store.New(ctx, cfg.S3)
			if err != nil {
				return err
			}
			disk, err := cache.New(cache.Options{
				Dir:      cfg.Cache.Dir,
				TTL:      cfg.Cache.TTL,
				MaxBytes: cfg.Cache.MaxBytes,
			})
			if err != nil {
				return err
			}
			defer disk.Close()
			disk.StartSweeper(ctx, cfg.Cache.SweepInterval, state.logger)

			reg := prometheus.NewRegistry()
			if err := metrics.RegisterRuntime(reg); err != nil {
				return err
			}
			met, err := metrics.New(reg)
			if err != nil {
				return err
			}
			if err := met.RegisterCacheUsage(func() (int, int64, error) {
				st, err := disk.Usage()
				return st.Entries, st.Bytes, err
			}); err != nil {
				return err
			}
			encFP := encrypt.Fingerprint(cfg.Encryption)
			fetch := service.NewFetch(store, enc).
				WithCache(disk, cfg.S3.Bucket, encFP).
				WithSoftTTL(cfg.Cache.SoftTTL).
				WithMetrics(met)
			keys := keying.Mapper{Prefix: cfg.S3.Prefix}
			scan := scanner.New(scanner.Options{
				FollowSymlinks: cfg.Archive.FollowSymlinks,
				Logger:         state.logger,
			})
			arch := service.NewArchive(scan, keys, store, enc, state.logger).WithMetrics(met)
			onChange, ok := identity.ParseOnChange(cfg.Archive.OnChange)
			if !ok {
				return fmt.Errorf("invalid archive.on_change %q", cfg.Archive.OnChange)
			}

			var s3Handler http.Handler
			if cfg.Server.S3APIEnabled() {
				virtBucket := cfg.Server.S3Bucket
				if virtBucket == "" {
					virtBucket = cfg.S3.Bucket
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
					OnChange:       onChange,
					Keys:           keys,
					Store:          store,
					Cache:          disk,
					BucketBackend:  cfg.S3.Bucket,
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
				Token:         cfg.Server.Token,
				Logger:        state.logger,
				Fetch:         fetch,
				Archive:       arch,
				OnChange:      onChange,
				Keys:          keys,
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
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "listening http=%s s3=%s metrics=%s\n",
				cfg.Server.Listen, s3Addr, cfg.Server.MetricsListen)
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

// newArchiveService builds archive/upload with either remote HTTP ingest or local S3+encrypt.
func newArchiveService(ctx context.Context, state *runState, cfg config.Config, keys keying.Mapper, dryRun bool) (*service.Archive, error) {
	scan := scanner.New(scanner.Options{
		FollowSymlinks: cfg.Archive.FollowSymlinks,
		Logger:         state.logger,
	})
	if cfg.Remote.URL != "" {
		if dryRun {
			return service.NewArchive(scan, keys, nil, encrypt.Passthrough{}, state.logger), nil
		}
		rc, err := remote.New(remote.Options{
			BaseURL:      cfg.Remote.URL,
			Token:        cfg.Server.Token,
			RateLimitBPS: cfg.Remote.RateLimitBPS,
		})
		if err != nil {
			return nil, err
		}
		return service.NewArchive(scan, keys, nil, encrypt.Passthrough{}, state.logger).WithRemote(rc), nil
	}
	enc, err := encrypt.New(cfg.Encryption)
	if err != nil {
		return nil, err
	}
	var store port.ObjectStore
	if !dryRun {
		st, err := s3store.New(ctx, cfg.S3)
		if err != nil {
			return nil, err
		}
		store = st
	}
	return service.NewArchive(scan, keys, store, enc, state.logger), nil
}
