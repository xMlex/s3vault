package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/domain"
)

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
