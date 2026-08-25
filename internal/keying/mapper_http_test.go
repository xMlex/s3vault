package keying

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/domain"
)

func TestMapperFromRequestPath(t *testing.T) {
	t.Parallel()
	m := Mapper{Prefix: "backups"}
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "nested", in: "logs/2026/application.log", want: "backups/logs/2026/application.log"},
		{name: "leading slash", in: "/logs/a.log", want: "backups/logs/a.log"},
		{name: "dot dot", in: "../secret", wantErr: true},
		{name: "nested escape", in: "foo/../../etc/passwd", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "too long", in: strings.Repeat("a", 2049), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := m.FromRequestPath(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, domain.ErrInvalidPath)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMapperFromRequestPathEmptyPrefix(t *testing.T) {
	t.Parallel()
	m := Mapper{}
	got, err := m.FromRequestPath("a.log")
	require.NoError(t, err)
	assert.Equal(t, "a.log", got)
}
