package container_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/container"
)

func sampleHeader(t *testing.T) container.Header {
	t.Helper()
	sum, err := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	tp, err := hex.DecodeString("afa43c43975fbfc700f051fd62016e1571e7e025")
	require.NoError(t, err)
	return container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 42,
		SHA256:        sum,
		Enc:           container.EncCommand,
		Wrap:          container.WrapNone,
		Thumbprint:    tp,
		Provider:      "cryptopro",
		SourceMTime:   time.Unix(1700000000, 0).UTC(),
	}
}

func TestMarshalParseRoundtrip(t *testing.T) {
	t.Parallel()
	h := sampleHeader(t)
	b, err := container.Marshal(h)
	require.NoError(t, err)
	assert.Len(t, b, container.HeaderSize)
	assert.True(t, container.IsMagic(b))

	got, err := container.Parse(b)
	require.NoError(t, err)
	assert.Equal(t, h.Version, got.Version)
	assert.Equal(t, h.PlaintextSize, got.PlaintextSize)
	assert.Equal(t, h.SHA256, got.SHA256)
	assert.Equal(t, h.Enc, got.Enc)
	assert.Equal(t, h.Wrap, got.Wrap)
	assert.Equal(t, h.Thumbprint, got.Thumbprint)
	assert.Equal(t, h.Provider, got.Provider)
	assert.Equal(t, h.SourceMTime, got.SourceMTime)
	assert.Equal(t, h.SHA256Hex(), got.SHA256Hex())
	assert.Equal(t, h.ThumbprintHex(), got.ThumbprintHex())
}

func TestMarshalNativeWrap(t *testing.T) {
	t.Parallel()
	sum, err := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	b, err := container.Marshal(container.Header{
		Version: container.VersionV1, SHA256: sum,
		Enc: container.EncNative, Wrap: container.WrapKEK,
	})
	require.NoError(t, err)
	got, err := container.Parse(b)
	require.NoError(t, err)
	assert.Equal(t, container.WrapKEK, got.Wrap)
	assert.Equal(t, "keyfile", container.WrapName(got.Wrap))
}

func TestParseRejectsBadCRC(t *testing.T) {
	t.Parallel()
	b, err := container.Marshal(sampleHeader(t))
	require.NoError(t, err)
	b[20] ^= 0xff
	_, err = container.Parse(b)
	require.ErrorIs(t, err, container.ErrCorruptHeader)
}

func TestParseRejectsWrongVersion(t *testing.T) {
	t.Parallel()
	b, err := container.Marshal(sampleHeader(t))
	require.NoError(t, err)
	b[8] = 99
	sum := crc32.ChecksumIEEE(b[0:124])
	binary.BigEndian.PutUint32(b[124:128], sum)
	_, err = container.Parse(b)
	require.ErrorIs(t, err, container.ErrCorruptHeader)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestParseRejectsNotContainer(t *testing.T) {
	t.Parallel()
	_, err := container.Parse(append([]byte("S3VLT01\n"), make([]byte, 120)...))
	require.ErrorIs(t, err, container.ErrNotContainer)
}

func TestParseShortHeader(t *testing.T) {
	t.Parallel()
	_, err := container.Parse([]byte(container.Magic))
	require.ErrorIs(t, err, container.ErrCorruptHeader)
}

func TestWriteUnwrapRoundtrip(t *testing.T) {
	t.Parallel()
	h := sampleHeader(t)
	var buf bytes.Buffer
	require.NoError(t, container.Write(&buf, h, bytes.NewReader([]byte("payload-bytes"))))

	got, payload, ok, err := container.Unwrap(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, h.SHA256Hex(), got.SHA256Hex())
	assert.Equal(t, "cryptopro", got.Provider)
	body, err := io.ReadAll(payload)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload-bytes"), body)
}

func TestUnwrapLegacyRestoresBytes(t *testing.T) {
	t.Parallel()
	raw := []byte("S3VLT01\nnot-a-container-but-long-enough-prefix-for-header-size-check-xxxxxxxxxxxxxxxx")
	_, payload, ok, err := container.Unwrap(bytes.NewReader(raw))
	require.NoError(t, err)
	require.False(t, ok)
	got, err := io.ReadAll(payload)
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

func TestUnwrapTruncatedContainer(t *testing.T) {
	t.Parallel()
	b, err := container.Marshal(sampleHeader(t))
	require.NoError(t, err)
	_, _, _, err = container.Unwrap(bytes.NewReader(b[:40]))
	require.ErrorIs(t, err, container.ErrCorruptHeader)
}

func TestEncWrapHelpers(t *testing.T) {
	t.Parallel()
	assert.Equal(t, container.EncNative, container.EncFromName("native"))
	assert.Equal(t, container.EncCommand, container.EncFromName("command"))
	assert.Equal(t, container.EncNone, container.EncFromName("none"))
	assert.Equal(t, "native", container.EncName(container.EncNative))
	assert.Equal(t, container.WrapRSA, container.WrapFromName("rsa-oaep"))
	assert.Equal(t, container.WrapRSA, container.WrapFromName("RSA-OAEP-256"))
	assert.Equal(t, container.WrapKEK, container.WrapFromName("keyfile"))
	assert.Equal(t, "rsa-oaep", container.WrapName(container.WrapRSA))
}

func FuzzParse(f *testing.F) {
	sum, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	b, err := container.Marshal(container.Header{
		Version: container.VersionV1, SHA256: sum, Enc: container.EncNone,
	})
	require.NoError(f, err)
	f.Add(b)
	f.Add([]byte(container.Magic))
	f.Add([]byte("S3VLT01\n" + string(make([]byte, 120))))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = container.Parse(data)
	})
}
