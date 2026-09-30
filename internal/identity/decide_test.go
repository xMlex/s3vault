package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/domain"
)

// Decide has no policy parameter: an existing object with different content is
// always overwritten. The old archive.on_change switch returned ActionOmit /
// ActionFail for skip/fail, which let the S3 facade answer 200 while discarding
// the uploaded body (docs/reliability-review.md H2).
func TestDecide(t *testing.T) {
	t.Parallel()

	sha := "abc"
	tests := []struct {
		name     string
		remote   domain.ObjectMeta
		expected Action
	}{
		{
			name:     "missing object",
			remote:   domain.ObjectMeta{},
			expected: ActionUpload,
		},
		{
			name: "same hash and size is a skip",
			remote: domain.ObjectMeta{
				Exists:      true,
				SHA256:      sha,
				ContentSize: 3,
			},
			expected: ActionSkip,
		},
		{
			name: "same hash without recorded size is a skip",
			remote: domain.ObjectMeta{
				Exists: true,
				SHA256: sha,
			},
			expected: ActionSkip,
		},
		{
			name: "same hash but different size must not skip",
			remote: domain.ObjectMeta{
				Exists:      true,
				SHA256:      sha,
				ContentSize: 4,
			},
			expected: ActionUpload,
		},
		{
			name: "changed content overwrites",
			remote: domain.ObjectMeta{
				Exists:      true,
				SHA256:      "other",
				ContentSize: 3,
			},
			expected: ActionUpload,
		},
		{
			name: "changed content without size overwrites",
			remote: domain.ObjectMeta{
				Exists: true,
				SHA256: "other",
			},
			expected: ActionUpload,
		},
		{
			name:     "legacy object without hash overwrites",
			remote:   domain.ObjectMeta{Exists: true},
			expected: ActionUpload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, Decide(sha, 3, tt.remote))
		})
	}
}
