package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/domain"
)

func TestParseOnChange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want OnChange
		ok   bool
	}{
		{name: "overwrite", in: "overwrite", want: OnChangeOverwrite, ok: true},
		{name: "skip", in: "skip", want: OnChangeSkip, ok: true},
		{name: "fail", in: "fail", want: OnChangeFail, ok: true},
		{name: "empty", in: "", want: OnChangeUnknown},
		{name: "unknown", in: "bogus", want: OnChangeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := ParseOnChange(tt.in)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestDecide(t *testing.T) {
	t.Parallel()

	sha := "abc"
	tests := []struct {
		name     string
		remote   domain.ObjectMeta
		onChange OnChange
		expected Action
	}{
		{
			name:     "missing object",
			remote:   domain.ObjectMeta{},
			onChange: OnChangeOverwrite,
			expected: ActionUpload,
		},
		{
			name: "same hash",
			remote: domain.ObjectMeta{
				Exists:      true,
				SHA256:      sha,
				ContentSize: 3,
			},
			onChange: OnChangeOverwrite,
			expected: ActionSkip,
		},
		{
			name: "changed overwrite",
			remote: domain.ObjectMeta{
				Exists:      true,
				SHA256:      "other",
				ContentSize: 3,
			},
			onChange: OnChangeOverwrite,
			expected: ActionUpload,
		},
		{
			name: "changed skip",
			remote: domain.ObjectMeta{
				Exists: true,
				SHA256: "other",
			},
			onChange: OnChangeSkip,
			expected: ActionOmit,
		},
		{
			name: "changed fail",
			remote: domain.ObjectMeta{
				Exists: true,
				SHA256: "other",
			},
			onChange: OnChangeFail,
			expected: ActionFail,
		},
		{
			name: "legacy object without hash",
			remote: domain.ObjectMeta{
				Exists: true,
			},
			onChange: OnChangeOverwrite,
			expected: ActionUpload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Decide(sha, 3, tt.remote, tt.onChange)
			assert.Equal(t, tt.expected, got)
		})
	}
}
