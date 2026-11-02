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
	"errors"
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
	// maxChunkSize bounds a chunk read from an object header. The header is
	// untrusted input: without a ceiling a corrupt object could ask for a
	// multi-gigabyte buffer before the first byte is authenticated.
	maxChunkSize = config.MaxNativeChunkSize
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
		chunk = config.DefaultNativeChunkSize
	}

	if chunk < 1 || chunk > config.MaxNativeChunkSize {
		// The operator-facing range is narrower (config.MinNativeChunkSize); the
		// constructor accepts any legal chunk so tests can exercise the framing
		// with small payloads.
		return nil, fmt.Errorf("native chunk size must be between 1 and %d bytes, got %d",
			config.MaxNativeChunkSize, chunk)
	}
	n := &Native{chunk: chunk, wrap: cfg.Wrap}
	switch cfg.Wrap {
	case "", WrapRSAOAEP:
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
	case WrapKeyfile:
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

// Name is the object-format name written into S3VCTR01.
func (n *Native) Name() string { return NameNative }

// Wrap returns the DEK wrap mode ("rsa-oaep" or "keyfile") for S3VCTR01.
func (n *Native) Wrap() string {
	switch n.wrap {
	case wrapRSA:
		return WrapRSAOAEP
	case wrapKEK:
		return WrapKeyfile
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
	// One ciphertext buffer for the whole stream: Seal appends the tag in place
	// at offset 4, so the 4-byte length prefix and the ciphertext leave in one
	// Write instead of two.
	sealed := make([]byte, 4+n.chunk+gcmOverhead)

	var nonce [12]byte
	var idx uint32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		nr, readErr := io.ReadFull(src, buf)
		if nr > 0 {
			if err := writeChunk(dst, aead, prefix, &nonce, idx, buf[:nr], sealed); err != nil {
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
	// Buffers are allocated once per stream, not once per chunk: at the default
	// 64 KiB chunk a 1 GiB object used to allocate ~2.2 GiB of short-lived
	// buffers (see BenchmarkNativeDecrypt).
	ct := make([]byte, hdr.Chunk+gcmOverhead)
	pt := make([]byte, 0, hdr.Chunk)

	var (
		nonce  [12]byte
		lenBuf [4]byte
		idx    uint32
	)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("chunk length: %w", err)
		}

		clen := binary.BigEndian.Uint32(lenBuf[:])
		if clen < gcmOverhead || int(clen) > len(ct) {
			return fmt.Errorf("invalid chunk length %d", clen)
		}

		if _, err := io.ReadFull(src, ct[:clen]); err != nil {
			return fmt.Errorf("truncated ciphertext: %w", err)
		}

		chunkNonce(&nonce, hdr.NoncePrefix, idx)

		plain, openErr := aead.Open(pt[:0], nonce[:], ct[:clen], nil)
		if openErr != nil {
			return fmt.Errorf("decrypt chunk %d: %w", idx, openErr)
		}

		if _, err := dst.Write(plain); err != nil {
			return err
		}
		idx++
	}
}

// writeChunk seals one plaintext chunk into buf and writes the framed result
// (4-byte length prefix followed by the ciphertext) with a single Write.
func writeChunk(dst io.Writer, aead cipher.AEAD, prefix []byte, nonce *[12]byte, idx uint32, pt, buf []byte) error {
	chunkNonce(nonce, prefix, idx)
	sealed := aead.Seal(buf[4:4], nonce[:], pt, nil)
	// The frame length is bounded by chunk+overhead (<= maxChunkSize+16).
	binary.BigEndian.PutUint32(buf[:4], uint32(len(sealed))) //nolint:gosec // bounded by maxChunkSize
	_, err := dst.Write(buf[:4+len(sealed)])
	return err
}

// chunkNonce fills dst with prefix || uint32 BE index.
func chunkNonce(dst *[12]byte, prefix []byte, idx uint32) {
	clear(dst[:])
	copy(dst[:], prefix)
	binary.BigEndian.PutUint32(dst[noncePrefix:], idx)
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

	return parseHeader(raw)
}

// ErrShortHeader means the buffer handed to ParseHeaderPrefix does not contain
// the whole S3VLT01 header. Callers can retry with a larger read or fall back to
// a sequential decrypt.
var ErrShortHeader = errors.New("native header: buffer too short")

// ParseHeaderPrefix parses an S3VLT01 header out of buf, which must start at the
// payload's first byte. It returns the header length in bytes.
func ParseHeaderPrefix(buf []byte) (hdrLen int, err error) {
	if len(buf) < len(magicV1)+4 {
		return 0, ErrShortHeader
	}

	if string(buf[:len(magicV1)]) != magicV1 {
		return 0, errors.New("unknown object format")
	}

	n := binary.BigEndian.Uint32(buf[len(magicV1):])
	if n == 0 || n > 1<<20 {
		return 0, errors.New("invalid header length")
	}

	total := len(magicV1) + 4 + int(n)
	if len(buf) < total {
		return 0, ErrShortHeader
	}

	if _, err := parseHeader(buf[len(magicV1)+4 : total]); err != nil {
		return 0, err
	}

	return total, nil
}

// parseHeader validates the JSON header emitted by Encrypt. The chunk size and
// nonce prefix are checked here, once, so no later allocation is driven by an
// unchecked value from the object.
func parseHeader(raw []byte) (headerV1, error) {
	var hdr headerV1
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return headerV1{}, fmt.Errorf("header json: %w", err)
	}
	if hdr.V != 1 || hdr.Alg != algChunked {
		return headerV1{}, fmt.Errorf("unsupported format version")
	}

	if hdr.Chunk <= 0 || hdr.Chunk > maxChunkSize {
		return headerV1{}, fmt.Errorf("invalid chunk size %d", hdr.Chunk)
	}

	if len(hdr.NoncePrefix) != noncePrefix {
		return headerV1{}, fmt.Errorf("invalid nonce prefix length %d", len(hdr.NoncePrefix))
	}
	return hdr, nil
}

// ChunkDecryptor decrypts single chunks of a native object. It exists for ranged
// reads: the payload is independently sealed per chunk, so a client asking for
// one range needs only the chunks covering it, not the whole object.
type ChunkDecryptor struct {
	aead   cipher.AEAD
	prefix []byte
	chunk  int
	hdrLen int
}

// HeaderLen is the length of the S3VLT01 header the payload begins with.
func (d *ChunkDecryptor) HeaderLen() int { return d.hdrLen }

// ChunkSize is the plaintext length of every chunk but the last.
func (d *ChunkDecryptor) ChunkSize() int { return d.chunk }

// NewChunkDecryptor parses the S3VLT01 header at the start of a native payload
// and unwraps its data key. buf must begin at the payload's first byte and
// contain the whole header (ErrShortHeader otherwise).
func (n *Native) NewChunkDecryptor(buf []byte) (*ChunkDecryptor, error) {
	hdrLen, err := ParseHeaderPrefix(buf)
	if err != nil {
		return nil, err
	}

	hdr, err := parseHeader(buf[len(magicV1)+4 : hdrLen])
	if err != nil {
		return nil, err
	}

	dek, err := n.unwrapDEK(hdr)
	if err != nil {
		return nil, err
	}

	aead, err := gcmFromDEK(dek)
	if err != nil {
		return nil, err
	}

	return &ChunkDecryptor{aead: aead, prefix: hdr.NoncePrefix, chunk: hdr.Chunk, hdrLen: hdrLen}, nil
}

// DecryptChunk decrypts one framed chunk: ct is the 4-byte big-endian
// ciphertext length followed by the ciphertext, exactly as stored. The plaintext
// is appended to dst.
func (d *ChunkDecryptor) DecryptChunk(dst []byte, idx uint32, ct []byte) ([]byte, error) {
	if len(ct) < 4 {
		return nil, fmt.Errorf("chunk %d: short frame", idx)
	}

	clen := binary.BigEndian.Uint32(ct[:4])
	if clen < gcmOverhead || int(clen) > d.chunk+gcmOverhead || int(clen) > len(ct)-4 {
		return nil, fmt.Errorf("chunk %d: invalid ciphertext length %d", idx, clen)
	}

	var nonce [12]byte
	chunkNonce(&nonce, d.prefix, idx)

	plain, err := d.aead.Open(dst, nonce[:], ct[4:4+clen], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt chunk %d: %w", idx, err)
	}

	return plain, nil
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
