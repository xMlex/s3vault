package keying

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapperKey(t *testing.T) {
	t.Parallel()

	root := filepath.FromSlash("/data/app")
	m := Mapper{Prefix: "backups"}

	tests := []struct {
		name     string
		abs      string
		expected string
		wantErr  bool
	}{
		{
			name:     "nested log",
			abs:      filepath.FromSlash("/data/app/logs/2026/application.log"),
			expected: "backups/logs/2026/application.log",
		},
		{
			name:     "top level",
			abs:      filepath.FromSlash("/data/app/file1.log"),
			expected: "backups/file1.log",
		},
		{
			name:    "escape parent",
			abs:     filepath.FromSlash("/data/other/x.log"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := m.Key(root, tt.abs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestMapperKeyEmptyPrefix(t *testing.T) {
	t.Parallel()
	m := Mapper{Prefix: ""}
	got, err := m.Key("/data/app", "/data/app/a.log")
	require.NoError(t, err)
	assert.Equal(t, "a.log", got)
}

func TestMapperKeyTrimsPrefixSlashes(t *testing.T) {
	t.Parallel()
	m := Mapper{Prefix: "/backups/"}
	got, err := m.Key("/data/app", "/data/app/x.log")
	require.NoError(t, err)
	assert.Equal(t, "backups/x.log", got)
}
