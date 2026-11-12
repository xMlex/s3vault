package service

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// windowRecorder returns a fetchFunc that records every requested window size
// and fills dst with a position-dependent pattern, so a wrong offset fails the
// byte comparison as well as the size assertion.
func windowRecorder(sizes *[]int) fetchFunc {
	return func(dst []byte, start int64) error {
		*sizes = append(*sizes, len(dst))

		for i := range dst {
			dst[i] = byte((start + int64(i)) % 251) //nolint:gosec // the modulus keeps the value in [0,250]
		}

		return nil
	}
}

func TestObjectReaderGrowsWindowOnSequentialRead(t *testing.T) {
	t.Parallel()

	const size = 8 << 20

	var sizes []int

	r := newObjectReader(t.Context(), size, windowRecorder(&sizes))
	t.Cleanup(func() { _ = r.Close() })

	buf := make([]byte, 32<<10)

	read := 0
	for read < 3<<20 {
		n, err := r.Read(buf)
		require.NoError(t, err)

		for i := range buf[:n] {
			require.Equal(t, byte((read+i)%251), buf[i])
		}

		read += n
	}

	require.GreaterOrEqual(t, len(sizes), 3)
	assert.Equal(t, []int{rangeWindow, 2 * rangeWindow, 4 * rangeWindow}, sizes[:3])
}

func TestObjectReaderSeekResetsWindow(t *testing.T) {
	t.Parallel()

	const size = 8 << 20

	var sizes []int

	r := newObjectReader(t.Context(), size, windowRecorder(&sizes))
	t.Cleanup(func() { _ = r.Close() })

	buf := make([]byte, 1<<20)

	_, err := io.ReadFull(r, buf)
	require.NoError(t, err)

	before := len(sizes)

	_, err = r.Seek(0, io.SeekStart)
	require.NoError(t, err)

	_, err = r.Read(buf[:1])
	require.NoError(t, err)

	require.Len(t, sizes, before+1)
	assert.Equal(t, rangeWindow, sizes[before])
}
