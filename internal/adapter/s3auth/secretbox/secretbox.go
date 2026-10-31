// Package secretbox encrypts the S3 secret keys stored in PostgreSQL.
//
// SigV4 verification needs the secret in plaintext, so it cannot be hashed. The
// database therefore holds AES-256-GCM ciphertext and the process keeps the
// 32-byte master key in S3VAULT_SERVER_AUTH_MASTER_KEY.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	// KeySize is the AES-256 key length.
	KeySize = 32
	// NonceSize is the standard GCM nonce length.
	NonceSize = 12
	// secretSize is the generated S3 secret length before base64.
	secretSize = 30
)

// ErrOpen reports a ciphertext that does not authenticate with the given key
// and associated data. It is a data/configuration error, not a bad password.
var ErrOpen = errors.New("secretbox: authentication failed")

// ParseKey decodes the base64 master key from the environment.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("master key is empty")
	}

	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}

	if len(key) != KeySize {
		return nil, fmt.Errorf("master key: must be %d bytes, got %d", KeySize, len(key))
	}

	return key, nil
}

// Seal encrypts plaintext with a fresh nonce. aad binds the ciphertext to a
// row, so copying it to another access key does not decrypt.
func Seal(key, plaintext []byte, aad string) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("secretbox nonce: %w", err)
	}

	return nonce, gcm.Seal(nil, nonce, plaintext, []byte(aad)), nil
}

// Open decrypts ciphertext and verifies its associated data.
func Open(key, nonce, ciphertext []byte, aad string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}

	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("secretbox: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, ErrOpen
	}

	return plaintext, nil
}

// GenerateSecret returns a new random S3 secret in a URL-safe, shell-friendly
// encoding. It is shown to the operator once and never stored in plaintext.
func GenerateSecret() (string, error) {
	b := make([]byte, secretSize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secret: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateKey returns a base64 master key, for bootstrap documentation and
// tests. The value must be kept in S3VAULT_SERVER_AUTH_MASTER_KEY.
func GenerateKey() (string, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("master key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox gcm: %w", err)
	}

	return gcm, nil
}
