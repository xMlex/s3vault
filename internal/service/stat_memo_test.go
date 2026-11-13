package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/domain"
)

const testETagV1 = `"v1"`

func TestStatSizeMemoRequiresVersion(t *testing.T) {
	t.Parallel()

	memo := newStatSizeMemo(4)
	memo.store("k", domain.ObjectMeta{}, 10)

	_, ok := memo.lookup("k", domain.ObjectMeta{})
	assert.False(t, ok, "an object without a validator cannot be memoized")

	meta := domain.ObjectMeta{ETag: testETagV1}
	memo.store("k", meta, 10)

	size, ok := memo.lookup("k", meta)
	assert.True(t, ok)
	assert.Equal(t, int64(10), size)

	_, ok = memo.lookup("k", domain.ObjectMeta{ETag: `"v2"`})
	assert.False(t, ok, "a new ETag is a different object version")
}

func TestStatSizeMemoEvictsOldest(t *testing.T) {
	t.Parallel()

	memo := newStatSizeMemo(2)
	modified := time.Unix(1700000000, 0)

	for i, key := range []string{"a", "b", "c"} {
		memo.store(key, domain.ObjectMeta{ETag: testETagV1, LastModified: modified}, int64(i))
	}

	_, ok := memo.lookup("a", domain.ObjectMeta{ETag: testETagV1, LastModified: modified})
	assert.False(t, ok, "the oldest entry is evicted first")

	size, ok := memo.lookup("c", domain.ObjectMeta{ETag: testETagV1, LastModified: modified})
	assert.True(t, ok)
	assert.Equal(t, int64(2), size)
}
