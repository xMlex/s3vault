package encrypt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

// wrapKEKName is the config spelling of the keyfile wrap.
const wrapKEKName = "keyfile"

func nativeWithChunk(t *testing.T, chunk int) *Native {
	t.Helper()

	keyPath := filepath.Join(t.TempDir(), "kek")
	kek := make([]byte, dekSize)
	_, err := rand.Read(kek)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, kek, 0o600))

	n, err := NewNative(config.NativeEnc{Wrap: wrapKEKName, KeyFile: keyPath, ChunkSize: chunk})
	require.NoError(t, err)

	return n
}

// TestChunkDecryptorRoundTrip is what ranged reads rely on: every chunk can be
// decrypted on its own, from the header alone.
func TestChunkDecryptorRoundTrip(t *testing.T) {
	t.Parallel()

	const (
		chunk       = 1024
		wrapKEKName = "keyfile"
	)

	plain := make([]byte, 3*chunk+77) // three full chunks and a short last one
	for i := range plain {
		plain[i] = byte(i % 251)
	}

	n := nativeWithChunk(t, chunk)

	var cipher bytes.Buffer
	require.NoError(t, n.Encrypt(context.Background(), &cipher, bytes.NewReader(plain)))

	dec, err := n.NewChunkDecryptor(cipher.Bytes())
	require.NoError(t, err)
	assert.Equal(t, chunk, dec.ChunkSize())

	base := int64(dec.HeaderLen())
	stride := int64(4 + chunk + gcmOverhead)

	tests := []struct {
		name string
		idx  uint32
	}{
		{name: "first", idx: 0},
		{name: "middle", idx: 1},
		{name: "last short", idx: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			offset := base + int64(tt.idx)*stride
			frame := cipher.Bytes()[offset:]
			clen := int(binary.BigEndian.Uint32(frame))
			require.NotZero(t, clen)

			got, err := dec.DecryptChunk(nil, tt.idx, frame[:4+clen])
			require.NoError(t, err)

			end := min(int64(tt.idx+1)*chunk, int64(len(plain)))
			assert.Equal(t, plain[int64(tt.idx)*chunk:end], got)
		})
	}
}

// TestChunkDecryptorRejectsHugeChunk keeps a corrupt header from turning into a
// multi-gigabyte allocation.
func TestChunkDecryptorRejectsHugeChunk(t *testing.T) {
	t.Parallel()

	hdr := headerV1{
		V:           1,
		Alg:         algChunked,
		Chunk:       1 << 30,
		NoncePrefix: make([]byte, noncePrefix),
		Wrap:        wrapKEK,
	}
	raw, err := json.Marshal(hdr)
	require.NoError(t, err)

	var payload bytes.Buffer
	payload.WriteString(magicV1)
	require.NoError(t, binary.Write(&payload, binary.BigEndian, uint32(len(raw)))) //nolint:gosec // test header is tiny
	payload.Write(raw)

	_, err = ParseHeaderPrefix(payload.Bytes())
	require.ErrorContains(t, err, "invalid chunk size")

	n := nativeWithChunk(t, 1024)
	require.ErrorContains(t, n.Decrypt(context.Background(), &bytes.Buffer{}, bytes.NewReader(payload.Bytes())),
		"invalid chunk size")
}

func TestParseHeaderPrefixShortBuffer(t *testing.T) {
	t.Parallel()

	_, err := ParseHeaderPrefix([]byte("S3VLT01\n"))
	require.ErrorIs(t, err, ErrShortHeader)
}
