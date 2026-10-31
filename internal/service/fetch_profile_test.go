package service

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/port"
)

type namedTestEncryptor struct {
	name string
}

func (n namedTestEncryptor) Encrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)

	return err
}

func (n namedTestEncryptor) Decrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)

	return err
}

func (n namedTestEncryptor) Name() string { return n.name }

func TestFetchEncryptorFor(t *testing.T) {
	t.Parallel()

	f := &Fetch{
		enc:      namedTestEncryptor{name: encrypt.NameNative},
		fallback: namedTestEncryptor{name: encrypt.NameCommand},
		managed:  true,
	}

	got, err := f.encryptorFor(encrypt.NameNative)
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameNative, encrypt.Name(got))

	got, err = f.encryptorFor(encrypt.NameCommand)
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameCommand, encrypt.Name(got))

	got, err = f.encryptorFor(encrypt.NameNone)
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameNone, encrypt.Name(got))

	_, err = f.encryptorFor("unknown")
	require.Error(t, err)

	base := &Fetch{enc: namedTestEncryptor{name: encrypt.NameNative}}
	got, err = base.encryptorFor(encrypt.NameCommand)
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameNative, encrypt.Name(got), "the base Fetch keeps its single encryptor")
}

func TestFetchLegacyEncryptor(t *testing.T) {
	t.Parallel()

	f := &Fetch{
		enc:      namedTestEncryptor{name: encrypt.NameCommand},
		fallback: namedTestEncryptor{name: encrypt.NameNative},
		managed:  true,
	}

	got, err := f.legacyEncryptor([]byte("S3VLT01\nrest"))
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameNative, encrypt.Name(got))

	got, err = f.legacyEncryptor([]byte("Salted__rest"))
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameCommand, encrypt.Name(got))

	got, err = f.legacyEncryptor([]byte("plain"))
	require.NoError(t, err)
	assert.Equal(t, encrypt.NameNone, encrypt.Name(got))

	_, err = (&Fetch{enc: namedTestEncryptor{name: encrypt.NameNone}, managed: true}).
		legacyEncryptor([]byte("S3VLT01\nrest"))
	require.Error(t, err)
}

func TestFetchDecryptStream(t *testing.T) {
	t.Parallel()

	f := &Fetch{
		enc:      namedTestEncryptor{name: encrypt.NameNative},
		fallback: namedTestEncryptor{name: encrypt.NameCommand},
		managed:  true,
	}

	var out bytes.Buffer
	require.NoError(t, f.decryptStream(context.Background(), &out, bytes.NewReader([]byte("plain")), ""))
	assert.Equal(t, "plain", out.String())

	out.Reset()
	require.NoError(t, f.decryptStream(context.Background(), &out, bytes.NewReader([]byte("data")), encrypt.NameNone))
	assert.Equal(t, "data", out.String())

	out.Reset()
	require.NoError(t, f.decryptStream(context.Background(), &out, bytes.NewReader([]byte("data")), encrypt.NameNative))
	assert.Equal(t, "data", out.String())

	out.Reset()
	err := f.decryptStream(context.Background(), &out, bytes.NewReader([]byte("data")), "unknown")
	require.Error(t, err)

	base := &Fetch{enc: encrypt.Passthrough{}}

	out.Reset()
	require.NoError(t, base.decryptStream(context.Background(), &out, bytes.NewReader([]byte("plain")), ""))
	assert.Equal(t, "plain", out.String())
}

var _ port.Encryptor = namedTestEncryptor{}
