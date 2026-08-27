package s3api

import (
	"encoding/xml"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
)

func (a *API) handleListBuckets(w http.ResponseWriter, r *http.Request, prin port.Principal) {
	type bucketXML struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	type result struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets struct {
			Bucket []bucketXML `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	out := result{}
	out.Owner.ID = prin.AccessKeyID
	out.Owner.DisplayName = prin.AccessKeyID
	out.Buckets.Bucket = []bucketXML{{
		Name:         a.bucket,
		CreationDate: time.Unix(0, 0).UTC().Format(time.RFC3339),
	}}
	a.writeXML(w, r, "list_buckets", out)
}

func (a *API) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if !a.bucketAsPrefix && !strings.EqualFold(bucket, a.bucket) {
		a.metric("head_bucket", "not_found")
		s3err.WriteError(w, r, s3err.NoSuchBucket, "")
		return
	}
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusOK)
	a.metric("head_bucket", "ok")
}

func (a *API) handleList(w http.ResponseWriter, r *http.Request, bucket string) {
	if !a.bucketAsPrefix && !strings.EqualFold(bucket, a.bucket) {
		a.metric("list", "not_found")
		s3err.WriteError(w, r, s3err.NoSuchBucket, "")
		return
	}
	q := r.URL.Query()
	clientPrefix := q.Get("prefix")
	opts := domain.ListOptions{
		Prefix:            a.listPrefix(bucket, clientPrefix),
		Delimiter:         q.Get("delimiter"),
		ContinuationToken: q.Get("continuation-token"),
		StartAfter:        q.Get("start-after"),
	}
	if mk := q.Get("max-keys"); mk != "" {
		n, err := strconv.ParseInt(mk, 10, 32)
		if err != nil || n < 0 {
			a.metric("list", "error")
			s3err.WriteError(w, r, s3err.InternalError, "invalid max-keys")
			return
		}
		opts.MaxKeys = int32(n)
	}
	page, err := a.store.List(r.Context(), opts)
	if err != nil {
		a.metric("list", "error")
		a.log.ErrorContext(r.Context(), "s3 list",
			slog.String("op", "s3.list"),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	type contentXML struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified,omitempty"`
		ETag         string `xml:"ETag,omitempty"`
		Size         int64  `xml:"Size"`
	}
	type prefixXML struct {
		Prefix string `xml:"Prefix"`
	}
	type listResult struct {
		XMLName               xml.Name     `xml:"ListBucketResult"`
		Name                  string       `xml:"Name"`
		Prefix                string       `xml:"Prefix"`
		Delimiter             string       `xml:"Delimiter,omitempty"`
		MaxKeys               int32        `xml:"MaxKeys"`
		IsTruncated           bool         `xml:"IsTruncated"`
		KeyCount              int32        `xml:"KeyCount"`
		ContinuationToken     string       `xml:"ContinuationToken,omitempty"`
		NextContinuationToken string       `xml:"NextContinuationToken,omitempty"`
		StartAfter            string       `xml:"StartAfter,omitempty"`
		Contents              []contentXML `xml:"Contents"`
		CommonPrefixes        []prefixXML  `xml:"CommonPrefixes"`
	}
	out := listResult{
		Name:                  bucket,
		Prefix:                clientPrefix,
		Delimiter:             opts.Delimiter,
		MaxKeys:               opts.MaxKeys,
		IsTruncated:           page.IsTruncated,
		KeyCount:              page.KeyCount,
		ContinuationToken:     opts.ContinuationToken,
		NextContinuationToken: page.NextContinuationToken,
		StartAfter:            opts.StartAfter,
	}
	if out.MaxKeys == 0 {
		out.MaxKeys = 1000
	}
	for _, obj := range page.Contents {
		item := contentXML{
			Key:  a.stripClientKey(bucket, obj.Key),
			Size: obj.Size,
			ETag: obj.ETag,
		}
		if !obj.LastModified.IsZero() {
			item.LastModified = obj.LastModified.UTC().Format(time.RFC3339)
		}
		out.Contents = append(out.Contents, item)
	}
	for _, p := range page.CommonPrefixes {
		out.CommonPrefixes = append(out.CommonPrefixes, prefixXML{
			Prefix: a.stripClientKey(bucket, p),
		})
	}
	a.writeXML(w, r, "list", out)
}

func (a *API) writeXML(w http.ResponseWriter, r *http.Request, op string, v any) {
	body, err := xml.Marshal(v)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
	a.metric(op, "ok")
}
