package keying

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRelative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "simple", in: "a/b.txt", want: "a/b.txt"},
		{name: "surrounding slashes", in: "/a/b/", want: "a/b"},
		{name: "surrounding spaces", in: " a/b ", want: "a/b"},
		{name: "dot segment", in: "a/./b", want: "a/b"},
		{name: "empty", in: "", wantErr: true},
		{name: "slash only", in: "/", wantErr: true},
		{name: "parent", in: "../x", wantErr: true},
		{name: "internal parent", in: "a/../../x", wantErr: true},
		{name: "backslash", in: `a\b`, wantErr: true},
		{name: "nul", in: "a\x00b", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateRelative(tt.in)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "simple", in: "tenant-a", want: "tenant-a"},
		{name: "nested", in: "/tenant-a/logs/", want: "tenant-a/logs"},
		{name: "spaces", in: " tenant-a ", want: "tenant-a"},
		{name: "empty", in: "", wantErr: true},
		{name: "double slash", in: "a//b", wantErr: true},
		{name: "parent", in: "a/../b", wantErr: true},
		{name: "backslash", in: `a\b`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizePrefix(tt.in)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJoinPrefix(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "a/b", JoinPrefix("a", "b"))
	assert.Equal(t, "a", JoinPrefix("a", ""))
	assert.Equal(t, "b", JoinPrefix("", "b"))
	assert.Empty(t, JoinPrefix("", ""))
	assert.Equal(t, "a/b", JoinPrefix("/a/", "/b/"))
}

func TestPrefixesOverlap(t *testing.T) {
	t.Parallel()

	assert.True(t, PrefixesOverlap("a", "a"))
	assert.True(t, PrefixesOverlap("a", "a/b"))
	assert.True(t, PrefixesOverlap("a/b", "a"))
	assert.False(t, PrefixesOverlap("a", "ab"))
	assert.False(t, PrefixesOverlap("a/b", "a/c"))
}

func TestIsCanonicalPrefix(t *testing.T) {
	t.Parallel()

	assert.True(t, IsCanonicalPrefix("a/b"))
	assert.False(t, IsCanonicalPrefix("/a/b"))
	assert.False(t, IsCanonicalPrefix("a//b"))
	assert.False(t, IsCanonicalPrefix(""))
}

func TestNormalizeOptionalPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "   ", want: ""},
		{in: "/", want: ""},
		{in: " /vault/ ", want: "vault"},
		{in: "vault/tenants", want: "vault/tenants"},
		{in: "a//b", wantErr: true},
		{in: "a/../b", wantErr: true},
		{in: "a\\b", wantErr: true},
		{in: "a\x00b", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NormalizeOptionalPrefix(tt.in)
		if tt.wantErr {
			assert.Error(t, err, tt.in)
			continue
		}

		assert.NoError(t, err, tt.in)
		assert.Equal(t, tt.want, got, tt.in)
	}

	assert.True(t, IsCanonicalOptionalPrefix(""))
	assert.True(t, IsCanonicalOptionalPrefix("a/b"))
	assert.False(t, IsCanonicalOptionalPrefix("/a/b"))
}
