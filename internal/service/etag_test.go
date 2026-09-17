package service

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/port"
)

// etagForHTTP must always yield an unquoted value: the HTTP and S3 handlers
// wrap it with strconv.Quote themselves. A double-quoted local synthetic ETag
// previously produced an invalid, escaped header.
func TestETagForHTTP(t *testing.T) {
	t.Parallel()
	const fallback = "deadbeef"
	tests := []struct {
		name string
		meta port.EntryMeta
		id   port.CacheID
		want string
	}{
		{name: "plaintext sha wins", meta: port.EntryMeta{SHA256: "abc", ETag: `"12-ff"`}, want: "abc"},
		{name: "quoted backend etag is unwrapped", meta: port.EntryMeta{ETag: `"12-ff"`}, want: "12-ff"},
		{name: "unquoted backend etag kept", meta: port.EntryMeta{ETag: "12-ff"}, want: "12-ff"},
		{name: "empty etag falls back to id", meta: port.EntryMeta{}, id: fallback, want: fallback},
		{name: "blank quoted etag falls back to id", meta: port.EntryMeta{ETag: `""`}, id: fallback, want: fallback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := etagForHTTP(tt.meta, tt.id)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, `"`, "handlers add the quotes")
			assert.NotEmpty(t, strconv.Quote(got))
		})
	}
}
