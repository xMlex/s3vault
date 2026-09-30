package encrypt

// DecryptAuto now branches on the object's S3VCTR01 `Enc` field, not on the
// concrete type of the local encryptor. These tests pin the fixed contract:
//   - the header's enc is authoritative; a reader whose mode does not match is
//     refused instead of silently copying ciphertext (P1/H2) or decrypting an
//     enc=0 payload (H5);
//   - objects without a container keep the pre-envelope detection (legacy).
//
// The old defect is described in problems.md P1 and docs/decrypt-detection.md.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

const (
	encNone    = "none"
	encNative  = "native"
	encCommand = "command"
)

// fakeEncryptor records whether Decrypt was reached and copies the payload.
// Name() is what DecryptAuto compares against the container's enc.
type fakeEncryptor struct {
	name      string
	decrypted bool
}

func (f *fakeEncryptor) Encrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}

func (f *fakeEncryptor) Decrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	f.decrypted = true
	_, err := io.Copy(dst, src)

	return err
}

func (f *fakeEncryptor) Name() string { return f.name }

// TestDecryptAutoHeaderDriven covers the container-present matrix: the enc in
// the header decides, and any mismatch with the reader's mode is an error.
func TestDecryptAutoHeaderDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		objEnc      string
		reader      string
		wantErr     string
		wantDecrypt bool
	}{
		{name: "none payload under none reader copies", objEnc: encNone, reader: encNone},
		{name: "command under command decrypts", objEnc: encCommand, reader: encCommand, wantDecrypt: true},
		{name: "native under native decrypts", objEnc: encNative, reader: encNative, wantDecrypt: true},
		// P1/H2: command ciphertext must not be copied as plaintext.
		{name: "command under none is refused", objEnc: encCommand, reader: encNone, wantErr: "requires encryption.mode=command"},
		{name: "native under none is refused", objEnc: encNative, reader: encNone, wantErr: "requires encryption.mode=native"},
		// H5: enc=0 means no layer to strip.
		{name: "none under command is refused", objEnc: encNone, reader: encCommand, wantErr: "requires encryption.mode=none"},
		{name: "none under native is refused", objEnc: encNone, reader: encNative, wantErr: "requires encryption.mode=none"},
		{name: "command under native is refused", objEnc: encCommand, reader: encNative, wantErr: "requires encryption.mode=command"},
		{name: "native under command is refused", objEnc: encNative, reader: encCommand, wantErr: "requires encryption.mode=native"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enc := &fakeEncryptor{name: tt.reader}
			payload := []byte("payload-bytes")

			var dst bytes.Buffer

			err := DecryptAuto(context.Background(), enc, tt.objEnc, &dst, bytes.NewReader(payload))

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.False(t, enc.decrypted, "decryptor must not run on a mode mismatch")
				assert.Empty(t, dst.String(), "nothing must be written on a mode mismatch")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantDecrypt, enc.decrypted)
			assert.Equal(t, string(payload), dst.String())
		})
	}
}

// TestDecryptAutoCommandRunsExternalProgram proves the command branch still
// dispatches to a real *Command when the header matches.
func TestDecryptAutoCommandRunsExternalProgram(t *testing.T) { //nolint:paralleltest // exec fixture: parallel script writes race with ETXTBSY
	cmd, marker := newRecordingCommand(t)

	payload := append([]byte("Salted__"), []byte("command-layer")...)

	var dst bytes.Buffer
	require.NoError(t, DecryptAuto(context.Background(), cmd, "command", &dst, bytes.NewReader(payload)))
	assert.FileExists(t, marker, "matching header must invoke the decrypt program")
	assert.Equal(t, string(payload), dst.String())
}

// TestDecryptAutoRefusesCommandMismatchWithRealCommand is the H2 read path:
// a command object seen by a non-command reader is refused before exec.
func TestDecryptAutoRefusesCommandMismatchWithRealCommand(t *testing.T) { //nolint:paralleltest // exec fixture
	cmd, marker := newRecordingCommand(t)

	var dst bytes.Buffer

	err := DecryptAuto(context.Background(), cmd, "none", &dst, bytes.NewReader([]byte("Salted__cipher")))
	require.ErrorContains(t, err, "requires encryption.mode=none")
	assert.NoFileExists(t, marker, "decrypt program must not run on a mode mismatch")
	assert.Empty(t, dst.String())
}

// TestDecryptAutoLegacy pins the no-container path: without an S3VCTR01 header
// there is no enc, so the local encryptor's type and the payload magic decide.
// Behaviour is deliberately unchanged for backward compatibility.
func TestDecryptAutoLegacy(t *testing.T) {
	t.Parallel()

	nativeCiphertext := append([]byte(magicV1), []byte("native-aead-body")...)
	commandCiphertext := append([]byte("Salted__"), []byte("openssl-ciphertext-body")...)

	tests := []struct {
		name        string
		reader      port.Encryptor
		input       []byte
		wantErr     bool
		wantDecrypt bool
	}{
		{
			name:    "none reader refuses native magic",
			reader:  Passthrough{},
			input:   nativeCiphertext,
			wantErr: true,
		},
		{
			name:   "none reader copies command ciphertext verbatim (legacy limit)",
			reader: Passthrough{},
			input:  commandCiphertext,
		},
		{
			name:   "none reader copies arbitrary plaintext",
			reader: Passthrough{},
			input:  []byte("just some plaintext"),
		},
		{
			name:        "native reader decrypts native magic",
			reader:      &fakeEncryptor{name: "native"},
			input:       nativeCiphertext,
			wantDecrypt: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var dst bytes.Buffer

			err := DecryptAuto(context.Background(), tt.reader, "", &dst, bytes.NewReader(tt.input))

			if tt.wantErr {
				require.ErrorContains(t, err, "object is encrypted")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, string(tt.input), dst.String())

			if f, ok := tt.reader.(*fakeEncryptor); ok {
				assert.Equal(t, tt.wantDecrypt, f.decrypted)
			}
		})
	}
}

// newRecordingCommand builds a *Command whose decrypt program writes a marker
// file and then copies stdin to stdout. It records that Decrypt was reached.
func newRecordingCommand(t *testing.T) (*Command, string) {
	t.Helper()

	dir := t.TempDir()
	marker := filepath.Join(dir, "decrypt-invoked")
	script := filepath.Join(dir, "fake-cryptcp")

	body := "#!/bin/sh\nset -eu\nprintf invoked > \"" + marker + "\"\ncat\n"
	// Write atomically (temp + rename) so the final path is never a file that
	// is still open for writing when execve checks it (ETXTBSY).
	tmp := script + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(body), 0o700)) //nolint:gosec // test fixture must be executable
	require.NoError(t, os.Rename(tmp, script))

	cmd, err := NewCommand(config.CommandEnc{
		Encrypt: []string{script},
		Decrypt: []string{script},
	})
	require.NoError(t, err)

	return cmd, marker
}
