package s3api

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
)

const (
	testClassifyBucket = "vault"
	testClassifyKey    = "a.txt"
	// testClassifyUpload is a syntactically valid uploadId; classify never
	// looks inside it, only at its presence.
	testClassifyUpload = "uploadId=X"
)

// classify must keep the existing operation set, add the five multipart
// operations on their query parameters, and only add a rejection for the two
// request shapes the facade recognises but does not serve: ListObjects v1 and
// the browser form POST. list-type=2 wins over a stray marker.
func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		bucket     string
		key        string
		rawQuery   string
		wantOp     port.S3Op
		wantReject s3err.Code
		wantOK     bool
	}{
		{name: "list buckets", method: http.MethodGet, wantOp: port.S3OpListBuckets, wantOK: true},
		{name: "list no query", method: http.MethodGet, bucket: testClassifyBucket, wantOp: port.S3OpList, wantOK: true},
		{name: "list v2", method: http.MethodGet, bucket: testClassifyBucket, rawQuery: "list-type=2", wantOp: port.S3OpList, wantOK: true},
		{name: "list v2 outranks marker", method: http.MethodGet, bucket: testClassifyBucket, rawQuery: "list-type=2&marker=x", wantOp: port.S3OpList, wantOK: true},
		{name: "list v1 marker", method: http.MethodGet, bucket: testClassifyBucket, rawQuery: "marker=x", wantOp: port.S3OpList, wantReject: s3err.NotImplemented, wantOK: true},
		{name: "list v1 explicit", method: http.MethodGet, bucket: testClassifyBucket, rawQuery: "list-type=1", wantOp: port.S3OpList, wantReject: s3err.NotImplemented, wantOK: true},
		{name: "get object", method: http.MethodGet, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpGet, wantOK: true},
		{name: "head bucket", method: http.MethodHead, bucket: testClassifyBucket, wantOp: port.S3OpHeadBucket, wantOK: true},
		{name: "head object", method: http.MethodHead, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpHead, wantOK: true},
		{name: "head no bucket", method: http.MethodHead, wantOp: port.S3OpUnknown, wantOK: false},
		{name: "put object", method: http.MethodPut, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpPut, wantOK: true},
		{name: "put bucket only", method: http.MethodPut, bucket: testClassifyBucket, wantOp: port.S3OpUnknown, wantOK: false},
		{name: "delete object", method: http.MethodDelete, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpDelete, wantOK: true},
		{name: "delete bucket only", method: http.MethodDelete, bucket: testClassifyBucket, wantOp: port.S3OpUnknown, wantOK: false},

		// Multipart: dispatched on the query, sharing verbs with the single-shot
		// operations. This table is the regression net for the 405 that a
		// >5 MiB upload used to hit, because POST had no case at all.
		{name: "create multipart", method: http.MethodPost, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: "uploads", wantOp: port.S3OpCreateMultipartUpload, wantOK: true},
		{name: "complete multipart", method: http.MethodPost, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: testClassifyUpload, wantOp: port.S3OpCompleteMultipartUpload, wantOK: true},
		{name: "post without multipart params is recognised", method: http.MethodPost, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpUnknown, wantReject: s3err.NotImplemented, wantOK: true},
		{name: "post bucket only", method: http.MethodPost, bucket: testClassifyBucket, wantOp: port.S3OpUnknown, wantOK: false},
		{name: "upload part", method: http.MethodPut, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: "partNumber=1&uploadId=X", wantOp: port.S3OpUploadPart, wantOK: true},
		{name: "put with uploadId but no partNumber is a put", method: http.MethodPut, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: testClassifyUpload, wantOp: port.S3OpPut, wantOK: true},
		{name: "put with partNumber but no uploadId is a put", method: http.MethodPut, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: "partNumber=1", wantOp: port.S3OpPut, wantOK: true},
		{name: "list parts", method: http.MethodGet, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: testClassifyUpload, wantOp: port.S3OpListParts, wantOK: true},
		{name: "abort multipart", method: http.MethodDelete, bucket: testClassifyBucket, key: testClassifyKey, rawQuery: testClassifyUpload, wantOp: port.S3OpAbortMultipartUpload, wantOK: true},
		{name: "method not allowed", method: http.MethodPatch, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpUnknown, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			query, err := url.ParseQuery(tc.rawQuery)
			require.NoError(t, err)

			op, reject, ok := classify(tc.method, tc.bucket, tc.key, query)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantOp, op)
			assert.Equal(t, tc.wantReject, reject)
		})
	}
}
