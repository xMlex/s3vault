package s3store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
)

// Store is an S3-compatible ObjectStore.
type Store struct {
	client *s3.Client
	bucket string
	put    *manager.Uploader
}

var _ port.ObjectStore = (*Store)(nil)

// New builds an S3 client from config (AWS or MinIO-style endpoint).
func New(ctx context.Context, cfg config.S3Config) (*Store, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 bucket is required")
	}
	// Re-checked at the point of use. The SDK would only complain about a too-small
	// part size at the first upload, naming neither the config key nor the S3
	// minimum. Zero means "not specified" here too, so a fragment assembled by
	// hand — as s3test.ConfigFromEnv does for the integration suite — gets the
	// documented default instead of failing.
	partSize := cfg.MultipartPartSize
	if partSize == 0 {
		partSize = config.DefaultMultipartPartSize
	}

	if partSize < config.MinMultipartPartSize {
		return nil, fmt.Errorf("s3.multipart_part_size: must be %d (default) or at least %d bytes (5 MiB), got %d",
			config.DefaultMultipartPartSize, config.MinMultipartPartSize, partSize)
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.AccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, cfg.SessionTok),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}

	clientOpts := []func(*s3.Options){
		func(o *s3.Options) {
			o.UsePathStyle = cfg.PathStyle
			if cfg.Endpoint != "" {
				o.BaseEndpoint = aws.String(cfg.Endpoint)
			}
		},
	}
	client := s3.NewFromConfig(awsCfg, clientOpts...)
	return &Store{
		client: client,
		bucket: cfg.Bucket,
		put: manager.NewUploader(client, func(u *manager.Uploader) { //nolint:staticcheck // the uploader s3vault itself uses, on purpose
			// The part size is this client's choice and travels with the request;
			// it is not negotiated with the store and not probed for. Raising it
			// cuts the number of parts (and of HTTP round trips) for a big file.
			// The cost is memory: the SDK keeps Concurrency+1 buffers of exactly
			// PartSize, so the 5 MiB default at concurrency 5 is ~30 MiB, and
			// every MiB added to the key adds ~5 MiB there. That is a deliberate
			// trade, not an oversight — see architecture.md.
			u.PartSize = partSize
		}),
	}, nil
}

func (s *Store) Head(ctx context.Context, key string) (domain.ObjectMeta, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return domain.ObjectMeta{Key: key, Exists: false}, nil
		}
		return domain.ObjectMeta{}, fmt.Errorf("head %s: %w", key, err)
	}
	meta := domain.ObjectMeta{
		Key:    key,
		Exists: true,
		ETag:   aws.ToString(out.ETag),
	}
	if out.ContentLength != nil {
		meta.Size = *out.ContentLength
	}
	if out.LastModified != nil {
		meta.LastModified = *out.LastModified
	}
	// Legacy objects may still carry s3vault-* user-metadata; new Puts do not write it.
	if out.Metadata != nil {
		fillObjectMeta(&meta, out.Metadata)
	}
	return meta, nil
}

func (s *Store) Put(ctx context.Context, key string, r io.Reader, meta domain.PutMeta) error {
	in := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   r,
	}
	if meta.ContentType != "" {
		in.ContentType = aws.String(meta.ContentType)
	}
	// A containerless object has no header to carry its identity, so it travels
	// in user-metadata instead. fillObjectMeta reads these keys back on HEAD,
	// which is what identity.ResolveRemote and Decide consume.
	if meta.PlaintextSHA256 != "" {
		in.Metadata = map[string]string{
			metaSHA256: meta.PlaintextSHA256,
			metaSize:   strconv.FormatInt(meta.PlaintextSize, 10),
		}
	}
	if _, err := s.put.Upload(ctx, in); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	return s.getObject(ctx, key, "")
}

func (s *Store) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	if start < 0 || end < start {
		return nil, domain.ObjectMeta{}, fmt.Errorf("get range %s: invalid range %d-%d", key, start, end)
	}
	return s.getObject(ctx, key, fmt.Sprintf("bytes=%d-%d", start, end))
}

func (s *Store) getObject(ctx context.Context, key, rangeHdr string) (io.ReadCloser, domain.ObjectMeta, error) {
	in := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}
	if rangeHdr != "" {
		in.Range = aws.String(rangeHdr)
	}

	out, err := s.client.GetObject(ctx, in, noCompositeChecksumWarning)
	if err != nil {
		if isNotFound(err) {
			return nil, domain.ObjectMeta{}, domain.ErrNotFound
		}
		return nil, domain.ObjectMeta{}, fmt.Errorf("get %s: %w", key, err)
	}
	meta := domain.ObjectMeta{Key: key, Exists: true, ETag: aws.ToString(out.ETag)}
	if out.ContentLength != nil {
		meta.Size = *out.ContentLength
	}
	if out.LastModified != nil {
		meta.LastModified = *out.LastModified
	}
	if out.Metadata != nil {
		fillObjectMeta(&meta, out.Metadata)
	}
	return out.Body, meta, nil
}

// noCompositeChecksumWarning silences "Skipped validation of multipart checksum"
// on every read of an object that was written as multipart.
//
// The chain behind the warning: manager.Uploader asks for CRC32 per part, so the
// store keeps a COMPOSITE checksum — on MinIO, x-amz-checksum-crc32: <base64>-3
// with ChecksumType COMPOSITE — and a checksum-of-checksums cannot be recomputed
// client-side. The SDK therefore skips verification and says so, once per GET, at
// WARN.
//
// Nothing actionable is lost, and the guarantee that does exist is the stronger
// one. Write-side integrity is untouched: the per-part CRC32 travels in the
// request and the store rejects any part that does not match it. What the warning
// denies is a *redundant* read-side re-check of a value no client can reproduce —
// true of every multipart-written object, so the line is constant rather than
// news, and identical on MinIO and on real S3 (AWS documents that clients cannot
// verify checksums of multipart-uploaded objects). Left on, it costs one WARN per
// read of every object over the part size, which is the shape of log an operator
// stops reading.
//
// It is a warning, not a failure: the read returns the correct bytes either way.
func noCompositeChecksumWarning(o *s3.Options) {
	o.DisableLogOutputChecksumValidationSkipped = true
}

func fillObjectMeta(meta *domain.ObjectMeta, md map[string]string) {
	meta.SHA256 = md[metaSHA256]
	meta.Encrypted = md[metaEnc]
	meta.FormatVersion = md[metaFormat]
	meta.CryptoProThumbprint = md[metaThumbprint]
	if sz := md[metaSize]; sz != "" {
		n, convErr := strconv.ParseInt(sz, 10, 64)
		if convErr == nil {
			meta.ContentSize = n
		}
	}
}

func isNotFound(err error) bool {
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NotFound", "NoSuchKey", "404":
			return true
		}
	}
	return false
}
