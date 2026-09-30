package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/port"
)

// Config is HTTP server construction input. The gateway's data frontend is the
// S3 API (S3Handler); this HTTP listener carries only the health/readiness
// probes and, when muxed, the S3 API itself.
type Config struct {
	Listen        string
	MetricsListen string
	S3Listen      string // empty = multiplex S3 on Listen
	Logger        *slog.Logger
	Store         port.ObjectStore
	Metrics       *metrics.Collector
	S3Handler     http.Handler // required SigV4 S3 API
}

// Server serves health probes and the S3 API facade.
type Server struct {
	listen        string
	metricsListen string
	s3Listen      string
	log           *slog.Logger
	store         port.ObjectStore
	handler       http.Handler
	s3Handler     http.Handler
	metricsH      http.Handler
}

// New validates bind policy and builds handlers.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("object store is required")
	}

	if err := requireS3API(cfg.S3Handler != nil); err != nil {
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

	s := &Server{
		listen:        cfg.Listen,
		metricsListen: cfg.MetricsListen,
		s3Listen:      cfg.S3Listen,
		log:           log,
		store:         cfg.Store,
		metricsH:      met.Handler(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	httpH := met.InstrumentHTTP(mux)

	s3H := met.InstrumentHTTP(cfg.S3Handler)
	s.s3Handler = s3H

	if cfg.S3Listen == "" {
		s.handler = dispatchHTTPOrS3(httpH, s3H)
	} else {
		s.handler = httpH
	}
	return s, nil
}

// Handler is the primary app mux (for tests).
func (s *Server) Handler() http.Handler { return s.handler }

// reservedHTTPFirstSegment is true for vault HTTP API paths (not S3).
func reservedHTTPFirstSegment(p string) bool {
	p = strings.Trim(p, "/")
	if p == "" {
		return false
	}
	seg, _, _ := strings.Cut(p, "/")
	switch strings.ToLower(seg) {
	case "health", "ready":
		return true
	default:
		return false
	}
}

func dispatchHTTPOrS3(httpH, s3H http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reservedHTTPFirstSegment(r.URL.Path) {
			httpH.ServeHTTP(w, r)
			return
		}
		s3H.ServeHTTP(w, r)
	})
}

// Run listens until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	app, appErr, err := s.start(s.listen, s.handler)
	if err != nil {
		return err
	}
	var (
		metricsSrv *http.Server
		s3Srv      *http.Server
		metErr     <-chan error
		s3Err      <-chan error
	)
	if s.metricsListen != "" {
		metricsSrv, metErr, err = s.start(s.metricsListen, s.metricsH)
		if err != nil {
			_ = app.Close()
			return err
		}
	}

	if s.s3Listen != "" {
		s3Only := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/health/" {
				s.handleHealth(w, r)
				return
			}
			s.s3Handler.ServeHTTP(w, r)
		})
		s3Srv, s3Err, err = s.start(s.s3Listen, s3Only)
		if err != nil {
			_ = app.Close()
			if metricsSrv != nil {
				_ = metricsSrv.Close()
			}
			return err
		}
	}

	s.log.InfoContext(ctx, "http listening",
		slog.String("op", "http"),
		slog.String("listen", s.listen),
		slog.String("s3_listen", s.s3Listen),
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
	case err := <-s3Err:
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
	if s3Srv != nil {
		err = errors.Join(err, s3Srv.Shutdown(shutdownCtx))
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
