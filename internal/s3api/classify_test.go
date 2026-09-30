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
)

// classify must keep the existing operation set and only add a rejection for
// ListObjects v1: list-type=2 wins over a stray marker, and the other
// operations are untouched.
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
		{name: "method not allowed", method: http.MethodPost, bucket: testClassifyBucket, key: testClassifyKey, wantOp: port.S3OpUnknown, wantOK: false},
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
