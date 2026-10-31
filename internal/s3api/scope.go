package s3api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/service"
)

// scope is the per-request view of a principal: the combined key namespace,
// the optional per-user encryption view, the optional destination store, and
// the isolated cache namespace.
//
// The encryption profile and the target store are resolved lazily. List/
// ListParts/Abort/HeadBucket do not need them and must keep working even if a
// key file referenced by the profile has disappeared after startup or the
// target's backend is unreachable.
type scope struct {
	api         *API
	principal   port.Principal
	target      *port.S3Target // nil = the gateway's global s3.*
	keys        keying.Mapper
	cacheBucket string
	targetNS    string

	store   port.ObjectStore
	profile *encrypt.Profile
	archive *service.Archive
	fetch   *service.Fetch
}

func (a *API) newScope(prin port.Principal) *scope {
	target := prin.User.Target

	basePrefix := a.keys.Prefix
	targetNS := ""

	if target != nil {
		// A target fully replaces the global s3.* location: its prefix is the
		// base, and the global s3.prefix does not participate.
		basePrefix = target.Prefix
		targetNS = s3target.Namespace(*target)
	}

	combined := keying.JoinPrefix(basePrefix, prin.User.Prefix)

	cacheBucket := a.bucketBackend
	if prin.User.ID != 0 {
		cacheBucket += "|user:" + strconv.FormatInt(prin.User.ID, 10)

		if target != nil {
			cacheBucket += "|s3:" + targetNS
		}
	}

	return &scope{
		api:         a,
		principal:   prin,
		target:      target,
		keys:        keying.Mapper{Prefix: combined},
		cacheBucket: cacheBucket,
		targetNS:    targetNS,
	}
}

func (s *scope) isUser() bool { return s.principal.User.ID != 0 }

// storeFor resolves the destination store. It is called only by operations that
// actually touch storage; CreateMultipartUpload and UploadPart use
// targetFingerprint instead, so an unavailable target does not block a session
// snapshot.
func (s *scope) storeFor(ctx context.Context) (port.ObjectStore, error) {
	if s.target == nil {
		return s.api.store, nil
	}

	if s.store != nil {
		return s.store, nil
	}

	if s.api.targets == nil {
		return nil, errors.New("target resolver is not configured")
	}

	store, err := s.api.targets.Store(ctx, *s.target)
	if err != nil {
		return nil, fmt.Errorf("user %d target: %w", s.principal.User.ID, err)
	}

	s.store = store

	return s.store, nil
}

// targetFingerprint identifies the destination for a multipart snapshot without
// building its store.
func (s *scope) targetFingerprint() string {
	if s.target == nil {
		return ""
	}

	return s3target.Fingerprint(*s.target)
}

func (s *scope) profileFor(_ context.Context) (*encrypt.Profile, error) {
	if !s.isUser() {
		return nil, errors.New("encryption profile requested for a static principal")
	}

	if s.profile != nil {
		return s.profile, nil
	}

	if s.api.profiles == nil {
		return nil, errors.New("encryption profile resolver is not configured")
	}

	p, err := s.api.profiles.ResolveRaw(s.principal.User.Encryption)
	if err != nil {
		return nil, fmt.Errorf("user %d encryption: %w", s.principal.User.ID, err)
	}

	s.profile = &p

	return s.profile, nil
}

func (s *scope) archiveFor(ctx context.Context) (*service.Archive, error) {
	if !s.isUser() {
		return s.api.archive, nil
	}

	if s.archive != nil {
		return s.archive, nil
	}

	p, err := s.profileFor(ctx)
	if err != nil {
		return nil, err
	}

	store, err := s.storeFor(ctx)
	if err != nil {
		return nil, err
	}

	s.archive = s.api.archive.WithStore(store).WithProfile(s.keys, p.Primary)

	return s.archive, nil
}

func (s *scope) fetchFor(ctx context.Context) (*service.Fetch, error) {
	if !s.isUser() {
		return s.api.fetch, nil
	}

	if s.fetch != nil {
		return s.fetch, nil
	}

	p, err := s.profileFor(ctx)
	if err != nil {
		return nil, err
	}

	store, err := s.storeFor(ctx)
	if err != nil {
		return nil, err
	}

	s.fetch = s.api.fetch.WithStore(store, s.targetNS).
		WithProfile(p.Primary, p.Fallback, s.cacheBucket, p.Fingerprint)

	return s.fetch, nil
}

func (s *scope) cacheFingerprint(ctx context.Context) (string, error) {
	if !s.isUser() {
		return s.api.encFP, nil
	}

	p, err := s.profileFor(ctx)
	if err != nil {
		return "", err
	}

	return p.Fingerprint, nil
}

func (s *scope) clientPath(bucket, clientKey string) string {
	return s.api.clientPath(bucket, clientKey)
}

func (s *scope) backendKey(bucket, clientKey string) (string, error) {
	return s.keys.FromRequestPath(s.clientPath(bucket, clientKey))
}

func (s *scope) listPrefix(bucket, clientPrefix string) (string, error) {
	rel := strings.TrimLeft(clientPrefix, "/")
	if s.api.bucketAsPrefix {
		rel = s.api.clientPath(bucket, clientPrefix)
	}

	if rel != "" {
		clean, err := keying.ValidateRelative(rel)
		if err != nil {
			return "", err
		}

		rel = clean
		if strings.HasSuffix(clientPrefix, "/") {
			rel += "/"
		}
	}

	server := strings.Trim(strings.ReplaceAll(s.keys.Prefix, "\\", "/"), "/")
	if server == "" {
		if s.api.bucketAsPrefix && strings.TrimLeft(clientPrefix, "/") == "" && rel != "" {
			return rel + "/", nil
		}

		return rel, nil
	}

	if rel == "" {
		return server + "/", nil
	}

	joined := path.Join(server, rel)
	if strings.HasSuffix(rel, "/") || (s.api.bucketAsPrefix && strings.TrimLeft(clientPrefix, "/") == "") {
		joined += "/"
	}

	return joined, nil
}

func (s *scope) startAfter(bucket, clientStartAfter string) (string, error) {
	if clientStartAfter == "" {
		return "", nil
	}

	return s.keys.FromRequestPath(s.clientPath(bucket, clientStartAfter))
}

func (s *scope) stripKey(bucket, key string) (string, bool) {
	server := strings.Trim(strings.ReplaceAll(s.keys.Prefix, "\\", "/"), "/")
	if server != "" {
		switch {
		case key == server:
			key = ""
		case strings.HasPrefix(key, server+"/"):
			key = strings.TrimPrefix(key, server+"/")
		default:
			return "", false
		}
	}

	if !s.api.bucketAsPrefix || bucket == "" {
		return key, true
	}

	switch {
	case key == bucket:
		return "", true
	case strings.HasPrefix(key, bucket+"/"):
		return strings.TrimPrefix(key, bucket+"/"), true
	default:
		return "", false
	}
}

func (s *scope) encodeToken(token string) string {
	if token == "" || !s.isUser() {
		return token
	}

	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

func (s *scope) decodeToken(token string) (string, error) {
	if token == "" || !s.isUser() {
		return token, nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("invalid continuation token: %w", err)
	}

	return string(raw), nil
}

// invalidateCache drops the plaintext entry for backendKey. It is best-effort:
// a failed or impossible profile lookup is logged and never fails the mutation
// that already succeeded.
func (s *scope) invalidateCache(ctx context.Context, backendKey, op string) {
	if s.api.cache == nil {
		return
	}

	fp, err := s.cacheFingerprint(ctx)
	if err != nil {
		s.api.log.WarnContext(ctx, "s3 cache invalidate skipped",
			slog.String("op", op),
			slog.String("err", err.Error()),
		)

		return
	}

	id := cache.ID(s.cacheBucket, backendKey, fp)
	if err := s.api.cache.Remove(ctx, id); err != nil {
		s.api.log.WarnContext(ctx, "s3 cache invalidate",
			slog.String("op", op),
			slog.String("err", err.Error()),
		)
	}
}
