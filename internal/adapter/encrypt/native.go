package encrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

const (
	magicV1     = "S3VLT01\n"
	algChunked  = "AES-256-GCM-CHUNK"
	wrapRSA     = "RSA-OAEP-256"
	wrapKEK     = "KEK-AES-GCM"
	gcmOverhead = 16
	dekSize     = 32
	noncePrefix = 8
)

type headerV1 struct {
	V           int    `json:"v"`
	Alg         string `json:"alg"`
	Chunk       int    `json:"chunk"`
	NoncePrefix []byte `json:"nonce_prefix"`
	Wrap        string `json:"wrap"`
	WrappedDEK  []byte `json:"wrapped_dek"`
	WrapNonce   []byte `json:"wrap_nonce,omitempty"`
}

// Native is envelope AES-256-GCM chunked encryption.
type Native struct {
	chunk      int
	wrap       string
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	kek        []byte
}

var _ port.Encryptor = (*Native)(nil)

// NewNative builds the built-in encryptor from config.
func NewNative(cfg config.NativeEnc) (*Native, error) {
	chunk := cfg.ChunkSize
	if chunk <= 0 {
		chunk = 65536
	}
	n := &Native{chunk: chunk, wrap: cfg.Wrap}
	switch cfg.Wrap {
	case "", "rsa-oaep":
		n.wrap = wrapRSA
		if cfg.PublicKeyPath != "" {
			pub, err := loadRSAPublic(cfg.PublicKeyPath)
			if err != nil {
				return nil, err
			}
			n.publicKey = pub
		}
		if cfg.PrivateKeyPath != "" {
			priv, err := loadRSAPrivate(cfg.PrivateKeyPath)
			if err != nil {
				return nil, err
			}
			n.privateKey = priv
			if n.publicKey == nil {
				n.publicKey = &priv.PublicKey
			}
		}
		if n.publicKey == nil && n.privateKey == nil {
			return nil, fmt.Errorf("native rsa-oaep requires public_key_path or private_key_path")
		}
	case "keyfile":
		n.wrap = wrapKEK
		if cfg.KeyFile == "" {
			return nil, fmt.Errorf("native keyfile wrap requires key_file")
		}
		kek, err := loadKEK(cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		n.kek = kek
	default:
		return nil, fmt.Errorf("unknown native wrap %q", cfg.Wrap)
	}
	return n, nil
}

func (n *Native) Name() string { return "native" }

// Wrap returns the DEK wrap mode ("rsa-oaep" or "keyfile") for S3VCTR01.
func (n *Native) Wrap() string {
	switch n.wrap {
	case wrapRSA:
		return "rsa-oaep"
	case wrapKEK:
		return "keyfile"
	default:
		return ""
	}
}

func (n *Native) Encrypt(ctx context.Context, dst io.Writer, src io.Reader) error {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("dek: %w", err)
	}
	prefix := make([]byte, noncePrefix)
	if _, err := rand.Read(prefix); err != nil {
		return fmt.Errorf("nonce prefix: %w", err)
	}
	wrapped, wrapNonce, err := n.wrapDEK(dek)
	if err != nil {
		return err
	}
	hdr := headerV1{
		V:           1,
		Alg:         algChunked,
		Chunk:       n.chunk,
		NoncePrefix: prefix,
		Wrap:        n.wrap,
		WrappedDEK:  wrapped,
		WrapNonce:   wrapNonce,
	}
	raw, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(dst, magicV1); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
	if _, err := dst.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := dst.Write(raw); err != nil {
		return err
	}
	aead, err := gcmFromDEK(dek)
	if err != nil {
		return err
	}
	buf := make([]byte, n.chunk)
	var idx uint32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		nr, readErr := io.ReadFull(src, buf)
		if nr > 0 {
			if err := writeChunk(dst, aead, prefix, idx, buf[:nr]); err != nil {
				return err
			}
			idx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (n *Native) Decrypt(ctx context.Context, dst io.Writer, src io.Reader) error {
	hdr, err := readHeader(src)
	if err != nil {
		return err
	}
	dek, err := n.unwrapDEK(hdr)
	if err != nil {
		return err
	}
	aead, err := gcmFromDEK(dek)
	if err != nil {
		return err
	}
	var idx uint32
	lenBuf := make([]byte, 4)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.ReadFull(src, lenBuf); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("chunk length: %w", err)
		}
		clen := binary.BigEndian.Uint32(lenBuf)
		if clen < gcmOverhead || clen > uint32(hdr.Chunk+gcmOverhead) {
			return fmt.Errorf("invalid chunk length %d", clen)
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(src, ct); err != nil {
			return fmt.Errorf("truncated ciphertext: %w", err)
		}
		pt, err := aead.Open(nil, chunkNonce(hdr.NoncePrefix, idx), ct, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", idx, err)
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		idx++
	}
}

func writeChunk(dst io.Writer, aead cipher.AEAD, prefix []byte, idx uint32, pt []byte) error {
	ct := aead.Seal(nil, chunkNonce(prefix, idx), pt, nil)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := dst.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := dst.Write(ct)
	return err
}

func chunkNonce(prefix []byte, idx uint32) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[8:], idx)
	return n
}

func gcmFromDEK(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func readHeader(src io.Reader) (headerV1, error) {
	magic := make([]byte, len(magicV1))
	if _, err := io.ReadFull(src, magic); err != nil {
		return headerV1{}, fmt.Errorf("magic: %w", err)
	}
	if string(magic) != magicV1 {
		return headerV1{}, fmt.Errorf("unknown object format")
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		return headerV1{}, fmt.Errorf("header length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1<<20 {
		return headerV1{}, fmt.Errorf("invalid header length")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(src, raw); err != nil {
		return headerV1{}, fmt.Errorf("header: %w", err)
	}
	var hdr headerV1
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return headerV1{}, fmt.Errorf("header json: %w", err)
	}
	if hdr.V != 1 || hdr.Alg != algChunked {
		return headerV1{}, fmt.Errorf("unsupported format version")
	}
	return hdr, nil
}

func (n *Native) wrapDEK(dek []byte) (wrapped, wrapNonce []byte, err error) {
	switch n.wrap {
	case wrapRSA:
		if n.publicKey == nil {
			return nil, nil, fmt.Errorf("rsa public key required to encrypt")
		}
		out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, n.publicKey, dek, nil)
		return out, nil, err
	case wrapKEK:
		aead, err := gcmFromDEK(n.kek)
		if err != nil {
			return nil, nil, err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, nil, err
		}
		return aead.Seal(nil, nonce, dek, nil), nonce, nil
	default:
		return nil, nil, fmt.Errorf("unknown wrap %s", n.wrap)
	}
}

func (n *Native) unwrapDEK(hdr headerV1) ([]byte, error) {
	switch hdr.Wrap {
	case wrapRSA:
		if n.privateKey == nil {
			return nil, fmt.Errorf("rsa private key required to decrypt")
		}
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, n.privateKey, hdr.WrappedDEK, nil)
	case wrapKEK:
		if len(n.kek) == 0 {
			return nil, fmt.Errorf("kek required to decrypt")
		}
		aead, err := gcmFromDEK(n.kek)
		if err != nil {
			return nil, err
		}
		return aead.Open(nil, hdr.WrapNonce, hdr.WrappedDEK, nil)
	default:
		return nil, fmt.Errorf("unknown wrap %s", hdr.Wrap)
	}
}

func loadKEK(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if len(b) == dekSize {
		return b, nil
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

func loadRSAPublic(path string) (*rsa.PublicKey, error) {
	block, err := pemBlock(path)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an rsa public key")
		}
		return pub, nil
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func loadRSAPrivate(path string) (*rsa.PrivateKey, error) {
	block, err := pemBlock(path)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an rsa private key")
	}
	return priv, nil
}

func pemBlock(path string) (*pem.Block, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no pem block in %s", path)
	}
	return block, nil
}
