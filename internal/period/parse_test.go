package period

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{name: "hours", input: "24h", expected: 24 * time.Hour},
		{name: "days", input: "7d", expected: 7 * 24 * time.Hour},
		{name: "thirty days", input: "30d", expected: 30 * 24 * time.Hour},
		{name: "week", input: "1w", expected: 7 * 24 * time.Hour},
		{name: "go minutes", input: "90m", expected: 90 * time.Minute},
		{name: "fractional day", input: "1.5d", expected: 36 * time.Hour},
		{name: "spaces", input: " 7d ", expected: 7 * 24 * time.Hour},
		{name: "empty", input: "", wantErr: true},
		{name: "garbage", input: "old", wantErr: true},
		{name: "negative", input: "-7d", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}
