package postgres

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeEntityName(t *testing.T) {
	t.Parallel()

	got, err := normalizeEntityName("  archive-a  ")
	require.NoError(t, err)
	assert.Equal(t, "archive-a", got)

	_, err = normalizeEntityName("")
	require.Error(t, err)

	_, err = normalizeEntityName(strings.Repeat("x", entityNameMax+1))
	require.Error(t, err)

	_, err = normalizeEntityName("bad\x00name")
	require.Error(t, err)
}

func TestNewEntityUID(t *testing.T) {
	t.Parallel()

	one, err := newEntityUID()
	require.NoError(t, err)
	two, err := newEntityUID()
	require.NoError(t, err)

	assert.Len(t, one, 32)
	assert.Len(t, two, 32)
	assert.NotEqual(t, one, two)
	assert.Regexp(t, `^[0-9a-f]{32}$`, one)
}

func TestIsGlobalEncryption(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "null", "{}", `{"mode":""}`, `{"mode":"  "}`} {
		assert.True(t, isGlobalEncryption([]byte(raw)), raw)
	}

	for _, raw := range []string{`{"mode":"none"}`, `{"mode":"native"}`, "not json"} {
		assert.False(t, isGlobalEncryption([]byte(raw)), raw)
	}
}
