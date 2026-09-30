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
		put:    manager.NewUploader(client),
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
	out, err := s.client.GetObject(ctx, in)
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
