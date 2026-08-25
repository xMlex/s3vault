package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/service"
)

// Config is HTTP server construction input.
type Config struct {
	Listen        string
	MetricsListen string
	Token         string
	Logger        *slog.Logger
	Fetch         *service.Fetch
	Archive       *service.Archive // optional; enables PUT /files/{path...}
	OnChange      identity.OnChange
	Keys          keying.Mapper
	Store         port.ObjectStore
	Metrics       *metrics.Collector
}

// Server serves decrypted objects from the plaintext cache and optionally accepts ingest.
type Server struct {
	listen        string
	metricsListen string
	token         string
	log           *slog.Logger
	fetch         *service.Fetch
	archive       *service.Archive
	onChange      identity.OnChange
	keys          keying.Mapper
	store         port.ObjectStore
	handler       http.Handler
	metricsH      http.Handler
}

// New validates bind/token policy and builds handlers.
func New(cfg Config) (*Server, error) {
	if cfg.Fetch == nil {
		return nil, fmt.Errorf("fetch service is required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("object store is required")
	}
	if err := checkBind(cfg.Listen, cfg.Token); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	met := cfg.Metrics
	if met == nil {
		var err error
		met, err = metrics.New(nil)
		if err != nil {
			return nil, err
		}
	}
	onChange := cfg.OnChange
	if onChange == identity.OnChangeUnknown {
		onChange = identity.OnChangeOverwrite
	}

	s := &Server{
		listen:        cfg.Listen,
		metricsListen: cfg.MetricsListen,
		token:         cfg.Token,
		log:           log,
		fetch:         cfg.Fetch,
		archive:       cfg.Archive,
		onChange:      onChange,
		keys:          cfg.Keys,
		store:         cfg.Store,
		metricsH:      met.Handler(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("GET /files/{path...}", s.handleFile)
	mux.HandleFunc("HEAD /files/{path...}", s.handleFile)
	mux.HandleFunc("PUT /files/{path...}", s.handleIngest)
	s.handler = met.InstrumentHTTP(s.withAuth(mux))
	return s, nil
}

// Handler is the file/health mux (for tests).
func (s *Server) Handler() http.Handler { return s.handler }

// Run listens until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	app, appErr, err := s.start(s.listen, s.handler)
	if err != nil {
		return err
	}
	var (
		metricsSrv *http.Server
		metErr     <-chan error
	)
	if s.metricsListen != "" {
		metricsSrv, metErr, err = s.start(s.metricsListen, s.metricsH)
		if err != nil {
			_ = app.Close()
			return err
		}
	}

	s.log.InfoContext(ctx, "http listening",
		slog.String("op", "http"),
		slog.String("listen", s.listen),
		slog.String("metrics_listen", s.metricsListen),
	)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-appErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case err := <-metErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	err = app.Shutdown(shutdownCtx)
	if metricsSrv != nil {
		err = errors.Join(err, metricsSrv.Shutdown(shutdownCtx))
	}
	return errors.Join(runErr, err)
}

func (s *Server) start(addr string, h http.Handler) (*http.Server, <-chan error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	return srv, errCh, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	_, err := s.store.Head(r.Context(), ".s3vault-ready")
	if err != nil {
		s.log.ErrorContext(r.Context(), "ready check", slog.String("op", "http"), slog.String("err", err.Error()))
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	rel := r.PathValue("path")
	key, err := s.keys.FromRequestPath(rel)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	cached, err := s.fetch.Materialize(r.Context(), key)
	if errors.Is(err, domain.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "materialize", slog.String("op", "http"), slog.String("err", err.Error()))
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	f, err := os.Open(cached.Path)
	if err != nil {
		s.log.ErrorContext(r.Context(), "open cache", slog.String("op", "http"), slog.String("err", err.Error()))
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", strconv.Quote(cached.ETag))
	http.ServeContent(w, r, cached.Name, cached.ModTime, f)
}
