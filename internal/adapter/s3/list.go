package s3store

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/xMlex/s3vault/internal/domain"
)

// List returns one page of objects (ListObjectsV2).
func (s *Store) List(ctx context.Context, opts domain.ListOptions) (domain.ListPage, error) {
	in := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	}
	if opts.Prefix != "" {
		in.Prefix = aws.String(opts.Prefix)
	}
	if opts.Delimiter != "" {
		in.Delimiter = aws.String(opts.Delimiter)
	}
	if opts.MaxKeys > 0 {
		in.MaxKeys = aws.Int32(opts.MaxKeys)
	}
	if opts.ContinuationToken != "" {
		in.ContinuationToken = aws.String(opts.ContinuationToken)
	}
	if opts.StartAfter != "" {
		in.StartAfter = aws.String(opts.StartAfter)
	}
	out, err := s.client.ListObjectsV2(ctx, in)
	if err != nil {
		return domain.ListPage{}, fmt.Errorf("list: %w", err)
	}
	page := domain.ListPage{
		IsTruncated:           aws.ToBool(out.IsTruncated),
		NextContinuationToken: aws.ToString(out.NextContinuationToken),
		KeyCount:              aws.ToInt32(out.KeyCount),
	}
	for _, obj := range out.Contents {
		item := domain.ListObject{
			Key:  aws.ToString(obj.Key),
			ETag: aws.ToString(obj.ETag),
		}
		if obj.Size != nil {
			item.Size = *obj.Size
		}
		if obj.LastModified != nil {
			item.LastModified = *obj.LastModified
		}
		page.Contents = append(page.Contents, item)
	}
	for _, p := range out.CommonPrefixes {
		if pref := aws.ToString(p.Prefix); pref != "" {
			page.CommonPrefixes = append(page.CommonPrefixes, pref)
		}
	}
	return page, nil
}
