package s3api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
)

// Config constructs the path-style S3 API facade.
type Config struct {
	Identity       port.S3Identity
	Region         string
	Bucket         string // virtual bucket name
	Fetch          *service.Fetch
	Archive        *service.Archive
	Keys           keying.Mapper
	Store          port.ObjectStore
	Cache          port.PlaintextCache // optional; invalidate on write and delete
	BucketBackend  string              // backend s3.bucket for cache.ID
	BucketAsPrefix bool                // treat client bucket as key prefix under backend
	EncFP          string
	Multipart      MultipartConfig // spool root, TTL, limits for multipart uploads
	Logger         *slog.Logger
	Metrics        *metrics.Collector // optional
}

// API is the S3 path-style gateway (plaintext facade over Fetch/Archive).
//
// There is no write-policy knob: PutObject always overwrites when the content
// differs. archive.on_change was removed because a global "do not write" policy
// answered 200 while discarding the uploaded bytes, and the gateway has no local
// source to fall back on (docs/reliability-review.md H2).
type API struct {
	id             port.S3Identity
	region         string
	bucket         string
	fetch          *service.Fetch
	archive        *service.Archive
	keys           keying.Mapper
	store          port.ObjectStore
	cache          port.PlaintextCache
	bucketBackend  string
	bucketAsPrefix bool
	encFP          string
	mp             *mpRegistry
	mpTTL          time.Duration
	mpMaxSessions  int
	mpMaxBytes     int64
	log            *slog.Logger
	metrics        *metrics.Collector
	v4             *awsig.V4[port.Principal]
}

// New validates config and builds the SigV4 verifier.
func New(cfg Config) (*API, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("s3 identity is required")
	}
	if cfg.Fetch == nil {
		return nil, fmt.Errorf("fetch service is required")
	}
	if cfg.Archive == nil {
		return nil, fmt.Errorf("archive service is required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("object store is required")
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("virtual bucket is required")
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	a := &API{
		id:             cfg.Identity,
		region:         region,
		bucket:         cfg.Bucket,
		fetch:          cfg.Fetch,
		archive:        cfg.Archive,
		keys:           cfg.Keys,
		store:          cfg.Store,
		cache:          cfg.Cache,
		bucketBackend:  cfg.BucketBackend,
		bucketAsPrefix: cfg.BucketAsPrefix,
		encFP:          cfg.EncFP,
		log:            log,
		metrics:        cfg.Metrics,
	}
	if a.bucketBackend == "" {
		a.bucketBackend = cfg.Bucket
	}

	// A zero-valued MultipartConfig gets the package defaults rather than an
	// error: the gateway must serve multipart in every configuration, and the
	// spool location is the only thing an operator has to be explicit about.
	mpCfg := cfg.Multipart
	if mpCfg.Dir == "" {
		mpCfg.Dir = DefaultMultipartDir
	}

	if mpCfg.TTL <= 0 {
		mpCfg.TTL = DefaultMultipartTTL
	}

	if mpCfg.MaxSessions <= 0 {
		mpCfg.MaxSessions = DefaultMultipartMaxSessions
	}

	mp, err := newMPRegistry(mpCfg, log)
	if err != nil {
		return nil, err
	}

	a.mp = mp
	a.mpTTL = mpCfg.TTL
	a.mpMaxSessions = mpCfg.MaxSessions
	a.mpMaxBytes = mpCfg.MaxBytes
	a.v4 = awsig.NewV4[port.Principal](&credProvider{id: cfg.Identity}, awsig.V4Config{
		Region:  region,
		Service: "s3",
	})
	return a, nil
}

// Handler returns the path-style S3 HTTP handler.
// Reserved first segments (health, ready, files) must be dispatched by the caller.
func (a *API) Handler() http.Handler {
	return http.HandlerFunc(a.serveHTTP)
}

func (a *API) serveHTTP(w http.ResponseWriter, r *http.Request) {
	bucket, key, ok := parsePath(r.URL.Path)
	if !ok {
		s3err.WriteError(w, r, s3err.InvalidBucketName, "")
		return
	}

	op, reject, ok := classify(r.Method, bucket, key, r.URL.Query())
	if !ok {
		a.metric("unknown", "method_not_allowed")
		s3err.WriteError(w, r, s3err.MethodNotAllowed, "")
		return
	}

	if reject != "" {
		a.metric(opMetric(op), "not_implemented")
		s3err.WriteError(w, r, reject, "")

		return
	}

	vr, err := a.v4.Verify(r)
	if err != nil {
		a.writeAuthError(w, r, op, err)
		return
	}
	prin := vr.AuthData()

	if err := a.id.Allow(r.Context(), prin, op, bucket, key); err != nil {
		a.metric(opMetric(op), "denied")
		a.log.WarnContext(r.Context(), "s3 access denied",
			slog.String("op", "s3."+opMetric(op)),
			slog.String("access_key_id", prin.AccessKeyID),
			slog.String("bucket", bucket),
		)
		s3err.WriteError(w, r, s3err.AccessDenied, "")
		return
	}

	switch op {
	case port.S3OpListBuckets:
		a.handleListBuckets(w, r, prin)
	case port.S3OpHeadBucket:
		a.handleHeadBucket(w, r, bucket)
	case port.S3OpList:
		a.handleList(w, r, bucket)
	case port.S3OpGet:
		a.handleGet(w, r, bucket, key, false)
	case port.S3OpHead:
		a.handleGet(w, r, bucket, key, true)
	case port.S3OpPut:
		a.handlePut(w, r, vr, bucket, key)
	case port.S3OpDelete:
		a.handleDelete(w, r, bucket, key)
	case port.S3OpCreateMultipartUpload:
		a.handleCreateMultipartUpload(w, r, bucket, key, prin)
	case port.S3OpUploadPart:
		a.handleUploadPart(w, r, vr, bucket, key, prin)
	case port.S3OpCompleteMultipartUpload:
		a.handleCompleteMultipartUpload(w, r, vr, bucket, key, prin)
	case port.S3OpAbortMultipartUpload:
		a.handleAbortMultipartUpload(w, r, bucket, key, prin)
	case port.S3OpListParts:
		a.handleListParts(w, r, bucket, key, prin)
	default:
		a.metric("unknown", "method_not_allowed")
		s3err.WriteError(w, r, s3err.MethodNotAllowed, "")
	}
}

func (a *API) metric(op, result string) {
	a.metrics.S3(op, result)
}

// invalidateCache drops the plaintext cache entry for backendKey so the next
// read cannot serve the version from before the write. It is called after every
// mutation the facade performs itself (PutObject, DeleteObject): the cache
// revalidates on its own schedule, but with soft_ttl > 0 a fresh entry is
// served without any revalidation, so without this a read straight after a
// successful write returns the previous content.
//
// Best-effort by design: a failed Remove only leaves the entry to the usual
// soft-TTL revalidation, so it must never fail the write that already succeeded.
func (a *API) invalidateCache(ctx context.Context, backendKey, op string) {
	if a.cache == nil {
		return
	}
	id := cache.ID(a.bucketBackend, backendKey, a.encFP)
	if err := a.cache.Remove(ctx, id); err != nil {
		a.log.WarnContext(ctx, "s3 cache invalidate",
			slog.String("op", op),
			slog.String("err", err.Error()),
		)
	}
}

func opMetric(op port.S3Op) string {
	switch op {
	case port.S3OpGet:
		return "get"
	case port.S3OpHead:
		return "head"
	case port.S3OpPut:
		return "put"
	case port.S3OpDelete:
		return "delete"
	case port.S3OpList:
		return "list"
	case port.S3OpHeadBucket:
		return "head_bucket"
	case port.S3OpListBuckets:
		return "list_buckets"
	case port.S3OpCreateMultipartUpload:
		return "create_multipart"
	case port.S3OpUploadPart:
		return "upload_part"
	case port.S3OpCompleteMultipartUpload:
		return "complete_multipart"
	case port.S3OpAbortMultipartUpload:
		return "abort_multipart"
	case port.S3OpListParts:
		return "list_parts"
	default:
		return "unknown"
	}
}

// reservedFirstSegments are HTTP routes; must not be S3 virtual bucket names.
var reservedFirstSegments = map[string]struct{}{
	"health": {},
	"ready":  {},
	"files":  {},
}

func parsePath(raw string) (bucket, key string, ok bool) {
	p := strings.Trim(raw, "/")
	if p == "" {
		return "", "", true
	}
	parts := strings.SplitN(p, "/", 2)
	bucket = parts[0]
	if bucket == "" {
		return "", "", false
	}
	if _, reserved := reservedFirstSegments[strings.ToLower(bucket)]; reserved {
		return "", "", false
	}
	if len(parts) == 2 {
		key = parts[1]
	}
	return bucket, key, true
}

// classify maps an HTTP request to an S3 operation. A non-empty reject code
// means the request is recognised but deliberately unsupported (ListObjects v1,
// browser form POST); the caller must answer with that error instead of
// dispatching op. ok is false when no operation matches the request at all.
//
// Multipart is dispatched on the query, not on the method: every one of its five
// operations reuses a verb that already means something else here (PUT is
// PutObject, POST is only Complete/Create, GET is GetObject, DELETE is
// DeleteObject). That is why the facade used to answer 405 to
// CreateMultipartUpload — POST had no case at all, so an upload of ~5 MiB or
// more failed at the router, before SigV4 and before the storage.
func classify(method, bucket, key string, query url.Values) (op port.S3Op, reject s3err.Code, ok bool) {
	hasUploadID := query.Has("uploadId")
	switch method {
	case http.MethodGet:
		return classifyGet(bucket, key, query)
	case http.MethodHead:
		if bucket == "" {
			return port.S3OpUnknown, "", false
		}
		if key == "" {
			return port.S3OpHeadBucket, "", true
		}

		return port.S3OpHead, "", true
	case http.MethodPost:
		return classifyPost(bucket, key, query, hasUploadID)
	case http.MethodPut:
		if bucket == "" || key == "" {
			return port.S3OpUnknown, "", false
		}

		if hasUploadID && query.Has("partNumber") {
			return port.S3OpUploadPart, "", true
		}

		return port.S3OpPut, "", true
	case http.MethodDelete:
		if bucket == "" || key == "" {
			return port.S3OpUnknown, "", false
		}

		if hasUploadID {
			return port.S3OpAbortMultipartUpload, "", true
		}

		return port.S3OpDelete, "", true
	default:
		return port.S3OpUnknown, "", false
	}
}

// classifyPost resolves a POST to Create or CompleteMultipartUpload.
//
// A bare POST is the browser form-upload shape (awsig can verify its policy
// document, but this facade serves no form posts). It is rejected as
// NotImplemented — "recognised, deliberately unsupported" — rather than
// MethodNotAllowed, which claims the verb is unknown and is what clients read as
// a broken endpoint.
func classifyPost(bucket, key string, query url.Values, hasUploadID bool) (port.S3Op, s3err.Code, bool) {
	if bucket == "" || key == "" {
		return port.S3OpUnknown, "", false
	}

	switch {
	case query.Has("uploads"):
		return port.S3OpCreateMultipartUpload, "", true
	case hasUploadID:
		return port.S3OpCompleteMultipartUpload, "", true
	default:
		return port.S3OpUnknown, s3err.NotImplemented, true
	}
}

// classifyGet resolves a GET to buckets, listing, a single object, or ListParts.
func classifyGet(bucket, key string, query url.Values) (port.S3Op, s3err.Code, bool) {
	switch {
	case bucket == "":
		return port.S3OpListBuckets, "", true
	case key == "":
		if isListV1(query) {
			return port.S3OpList, s3err.NotImplemented, true
		}

		return port.S3OpList, "", true
	case query.Has("uploadId"):
		return port.S3OpListParts, "", true
	default:
		return port.S3OpGet, "", true
	}
}

// isListV1 reports whether a GET on a bucket is a ListObjects (v1) request.
// v1 is signalled by an explicit list-type other than "2", or, per S3 wire
// reality, by a marker parameter when list-type is absent. ListObjectsV2
// (list-type=2, or no list-type and no marker) is the only listing this facade
// implements; a v1 request is answered with NotImplemented instead of a V2 body.
func isListV1(query url.Values) bool {
	if query.Has("list-type") {
		return query.Get("list-type") != "2"
	}

	return query.Has("marker")
}

// clientPath joins the request bucket into the relative object path when
// BucketAsPrefix is set: s3://reports/a.log → "reports/a.log" (then + s3.prefix).
func (a *API) clientPath(bucket, clientKey string) string {
	clientKey = strings.TrimLeft(clientKey, "/")
	if !a.bucketAsPrefix {
		return clientKey
	}
	if clientKey == "" {
		return bucket
	}
	return path.Join(bucket, clientKey)
}

func (a *API) backendKey(bucket, clientKey string) (string, error) {
	return a.keys.FromRequestPath(a.clientPath(bucket, clientKey))
}

func (a *API) listPrefix(bucket, clientPrefix string) string {
	rel := strings.TrimLeft(clientPrefix, "/")
	if a.bucketAsPrefix {
		rel = a.clientPath(bucket, clientPrefix)
	}
	server := strings.Trim(strings.ReplaceAll(a.keys.Prefix, "\\", "/"), "/")
	if server == "" {
		if a.bucketAsPrefix && strings.TrimLeft(clientPrefix, "/") == "" && rel != "" {
			return rel + "/"
		}
		return rel
	}
	if rel == "" {
		return server + "/"
	}
	joined := path.Join(server, rel)
	if a.bucketAsPrefix && strings.TrimLeft(clientPrefix, "/") == "" {
		return joined + "/"
	}
	return joined
}

func (a *API) stripServerPrefix(key string) string {
	server := strings.Trim(strings.ReplaceAll(a.keys.Prefix, "\\", "/"), "/")
	if server == "" {
		return key
	}
	prefix := server + "/"
	if strings.HasPrefix(key, prefix) {
		return strings.TrimPrefix(key, prefix)
	}
	if key == server {
		return ""
	}
	return key
}

// stripClientKey removes server prefix and, when BucketAsPrefix, the bucket segment
// so ListObjects keys match what the client sent inside that bucket.
func (a *API) stripClientKey(bucket, key string) string {
	key = a.stripServerPrefix(key)
	if !a.bucketAsPrefix || bucket == "" {
		return key
	}
	prefix := bucket + "/"
	if strings.HasPrefix(key, prefix) {
		return strings.TrimPrefix(key, prefix)
	}
	if key == bucket {
		return ""
	}
	return key
}
