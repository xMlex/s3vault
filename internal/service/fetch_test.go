package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/service"
)

// containedPayload builds S3VCTR01 || payload with the requested enc byte.
func containedPayload(t *testing.T, enc uint8, payload []byte) []byte {
	t.Helper()

	sum := sha256.Sum256(payload)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(payload)),
		SHA256:        sum[:],
		Enc:           enc,
	})
	require.NoError(t, err)

	return append(hdr, payload...)
}

// recordingCommand returns a *Command whose decrypt program copies stdin to
// stdout and touches marker, so tests can prove Decrypt was (not) invoked.
func recordingCommand(t *testing.T, marker string) *encrypt.Command {
	t.Helper()
	script := filepath.Join(t.TempDir(), "fake-cryptcp")
	body := "#!/bin/sh\nset -eu\nprintf invoked > \"" + marker + "\"\ncat\n"
	require.NoError(t, os.WriteFile(script, []byte(body), 0o700)) //nolint:gosec // test fixture must be executable
	enc, err := encrypt.NewCommand(config.CommandEnc{
		Encrypt: []string{script},
		Decrypt: []string{script},
	})
	require.NoError(t, err)

	return enc
}

// TestFetchDownloadRefusesEncMismatch is the P1 read path: a command-encrypted
// object read with mode=none must fail loudly, not write ciphertext.
func TestFetchDownloadRefusesEncMismatch(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k",
		bytes.NewReader(containedPayload(t, container.EncCommand, []byte("Salted__ciphertext"))), domain.PutMeta{}))

	dest := filepath.Join(t.TempDir(), "out.bin")
	err := service.NewFetch(store, encrypt.Passthrough{}).Download(context.Background(), "k", dest, io.Discard)

	require.ErrorContains(t, err, "requires encryption.mode=command")

	_, statErr := os.Stat(dest)
	assert.True(t, os.IsNotExist(statErr), "no output must be left on a mode mismatch")
}

// TestFetchDownloadRefusesEncNoneWithCommandReader is H5: enc=0 means there is
// no layer to strip, so the decrypt program must not run.
func TestFetchDownloadRefusesEncNoneWithCommandReader(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k",
		bytes.NewReader(containedPayload(t, container.EncNone, []byte("plaintext"))), domain.PutMeta{}))

	marker := filepath.Join(t.TempDir(), "invoked")
	enc := recordingCommand(t, marker)
	dest := filepath.Join(t.TempDir(), "out.bin")

	err := service.NewFetch(store, enc).Download(context.Background(), "k", dest, io.Discard)

	require.ErrorContains(t, err, "requires encryption.mode=none")
	assert.NoFileExists(t, marker, "decrypt program must not run for enc=0")
}

// TestFetchDownloadEncryptedRoundTrip keeps the symmetric contract: enc=command
// with a command reader still decrypts.
func TestFetchDownloadEncryptedRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte("hello container")
	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k",
		bytes.NewReader(containedPayload(t, container.EncCommand, payload)), domain.PutMeta{}))

	marker := filepath.Join(t.TempDir(), "invoked")
	enc := recordingCommand(t, marker)
	dest := filepath.Join(t.TempDir(), "out")

	require.NoError(t, service.NewFetch(store, enc).Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest) //nolint:gosec // dest is a test temp file
	require.NoError(t, err)
	assert.Equal(t, string(payload), string(b))
	assert.FileExists(t, marker)
}

// TestFetchDownloadContainerlessRead covers objects without an S3VCTR01
// container. The reader's own encryption.mode decides how loud that is: mode=none
// writes such objects itself, so it is quiet; an encrypting reader meeting one is
// reading something it did not write and says so.
func TestFetchDownloadContainerlessRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		enc       port.Encryptor
		wantLog   string
		wantNoLog string
	}{
		{
			name:      "none reader stays quiet on its own object shape",
			enc:       encrypt.Passthrough{},
			wantNoLog: "level=WARN",
		},
		{
			name:    "encrypting reader warns about an unexpected shape",
			enc:     &namedEncryptor{name: "native"},
			wantLog: "legacy detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newMemStore()
			require.NoError(t, store.Put(context.Background(), "k",
				bytes.NewReader([]byte("bare plaintext")), domain.PutMeta{
					PlaintextSHA256: "d0",
					PlaintextSize:   13,
				}))

			var logs bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&logs, nil))

			dest := filepath.Join(t.TempDir(), "out")
			require.NoError(t, service.NewFetch(store, tt.enc).WithLogger(logger).
				Download(context.Background(), "k", dest, io.Discard))

			b, err := os.ReadFile(dest) //nolint:gosec // dest is a test temp file
			require.NoError(t, err)
			assert.Equal(t, "bare plaintext", string(b))

			if tt.wantLog != "" {
				assert.Contains(t, logs.String(), tt.wantLog)
			}

			if tt.wantNoLog != "" {
				assert.NotContains(t, logs.String(), tt.wantNoLog)
			}
		})
	}
}

// A read is the last hop on the path, so a layer the reader cannot remove is
// drift: it must be reported rather than written to disk.
// A read is the last hop on the path, so a layer the reader cannot remove is
// drift: it must be reported rather than written to disk.
func TestFetchReadRefusesForeignLayer(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	payload := []byte("Salted__ciphertext")
	body := containedPayload(t, container.EncCommand, payload)
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader(body), domain.PutMeta{}))

	_, err := service.NewFetch(store, encrypt.Passthrough{}).Materialize(context.Background(), "k")
	require.ErrorContains(t, err, "requires encryption.mode=command")
}

func TestFetchDownloadPlain(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader([]byte("hello")), domain.PutMeta{}))
	dest := filepath.Join(t.TempDir(), "out.log")
	f := service.NewFetch(store, encrypt.Passthrough{})
	require.NoError(t, f.Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(b))
}

func TestFetchDownloadUsesContainerThumbprint(t *testing.T) {
	t.Parallel()
	headerTP := "cccccccccccccccccccccccccccccccccccccccc"
	sum, err := container.SHA256FromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	tp, err := container.ThumbprintFromHex(headerTP)
	require.NoError(t, err)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 6,
		SHA256:        sum,
		Enc:           container.EncCommand,
		Provider:      "cryptopro",
		Thumbprint:    tp,
	})
	require.NoError(t, err)

	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader(append(hdr, []byte("cipher")...)), domain.PutMeta{}))

	dir := t.TempDir()
	script := filepath.Join(dir, "echo-tp.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$CRYPTOPRO_THUMBPRINT\"\n"), 0o700))
	enc, err := encrypt.NewCommand(config.CommandEnc{
		Encrypt:    []string{script},
		Decrypt:    []string{script},
		Thumbprint: "dddddddddddddddddddddddddddddddddddddddd",
	})
	require.NoError(t, err)

	dest := filepath.Join(t.TempDir(), "out")
	f := service.NewFetch(store, enc)
	require.NoError(t, f.Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, headerTP, string(b))
}

func TestFetchDownloadPrefersContainerThumbprintOverConfig(t *testing.T) {
	t.Parallel()
	headerTP := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfgTP := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sum, err := container.SHA256FromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	tp, err := container.ThumbprintFromHex(headerTP)
	require.NoError(t, err)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 1,
		SHA256:        sum,
		Enc:           container.EncCommand,
		Provider:      "cryptopro",
		Thumbprint:    tp,
	})
	require.NoError(t, err)

	store := newMemStore()
	require.NoError(t, store.Put(context.Background(), "k", bytes.NewReader(append(hdr, []byte("x")...)), domain.PutMeta{}))

	dir := t.TempDir()
	script := filepath.Join(dir, "echo-tp.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s' \"$CRYPTOPRO_THUMBPRINT\"\n"), 0o700))
	enc, err := encrypt.NewCommand(config.CommandEnc{
		Encrypt: []string{script}, Decrypt: []string{script}, Thumbprint: cfgTP,
	})
	require.NoError(t, err)

	dest := filepath.Join(t.TempDir(), "out")
	require.NoError(t, service.NewFetch(store, enc).Download(context.Background(), "k", dest, io.Discard))
	b, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, headerTP, string(b))
}
