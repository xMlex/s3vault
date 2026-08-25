// Package container implements the S3VCTR01 object envelope: a fixed binary
// header carrying plaintext identity, encryption mode, wrap, and command
// provider ahead of the opaque payload (identity without S3 user-metadata).
package container

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"time"
	"unicode"
)

const (
	// Magic is the 8-byte object container identifier (no trailing newline;
	// distinct from native crypto magic "S3VLT01\n").
	Magic = "S3VCTR01"
	// VersionV1 is the only supported header version.
	VersionV1 = 1
	// HeaderSize is the fixed v1 header length in bytes (Range bytes=0-127).
	HeaderSize = 128
	// FormatVersion is the string form of the container magic.
	FormatVersion = "S3VCTR01"

	EncNone    uint8 = 0
	EncNative  uint8 = 1
	EncCommand uint8 = 2

	WrapNone uint8 = 0
	WrapRSA  uint8 = 1 // RSA-OAEP-256
	WrapKEK  uint8 = 2 // KEK-AES-GCM

	sha256Len     = 32
	thumbprintLen = 20
	providerMax   = 32
	crcOffset     = 124
)

var (
	// ErrNotContainer means the leading bytes are not S3VCTR01.
	ErrNotContainer = errors.New("not an S3VCTR01 container")
	// ErrCorruptHeader means magic matched but CRC/version/length failed.
	ErrCorruptHeader = errors.New("corrupt S3VCTR01 header")
)

// Header is the decoded fixed container prefix.
type Header struct {
	Version       uint8
	Flags         uint8
	PlaintextSize int64
	SHA256        []byte // 32 raw bytes
	Enc           uint8
	Wrap          uint8
	Thumbprint    []byte // 0 or 20 raw SHA-1 bytes
	Provider      string // command provider name (ASCII), empty if unused
	SourceMTime   time.Time
}

// Marshal encodes a v1 header (exactly HeaderSize bytes).
func Marshal(h Header) ([]byte, error) {
	if len(h.SHA256) != sha256Len {
		return nil, fmt.Errorf("container: sha256 must be %d bytes", sha256Len)
	}
	tp := h.Thumbprint
	var tpLen uint8
	switch {
	case len(tp) == 0:
		tp = make([]byte, thumbprintLen)
	case len(tp) == thumbprintLen:
		tpLen = thumbprintLen
	default:
		return nil, fmt.Errorf("container: thumbprint must be 0 or %d bytes", thumbprintLen)
	}
	enc := h.Enc
	switch enc {
	case EncNone, EncNative, EncCommand:
	default:
		return nil, fmt.Errorf("container: unknown enc %d", enc)
	}
	wrap := h.Wrap
	switch wrap {
	case WrapNone, WrapRSA, WrapKEK:
	default:
		return nil, fmt.Errorf("container: unknown wrap %d", wrap)
	}
	provider, provLen, err := encodeProvider(h.Provider)
	if err != nil {
		return nil, err
	}
	ver := h.Version
	if ver == 0 {
		ver = VersionV1
	}
	if ver != VersionV1 {
		return nil, fmt.Errorf("container: unsupported version %d", ver)
	}

	buf := make([]byte, HeaderSize)
	copy(buf[0:8], Magic)
	buf[8] = ver
	buf[9] = h.Flags
	binary.BigEndian.PutUint16(buf[10:12], HeaderSize)
	binary.BigEndian.PutUint64(buf[12:20], uint64(h.PlaintextSize))
	copy(buf[20:52], h.SHA256)
	buf[52] = enc
	buf[53] = wrap
	buf[54] = tpLen
	buf[55] = provLen
	copy(buf[56:76], tp)
	var mtime int64
	if !h.SourceMTime.IsZero() {
		mtime = h.SourceMTime.UTC().Unix()
	}
	binary.BigEndian.PutUint64(buf[76:84], uint64(mtime))
	copy(buf[84:116], provider)
	// 116..123 reserved zeros
	crc := crc32.ChecksumIEEE(buf[0:crcOffset])
	binary.BigEndian.PutUint32(buf[crcOffset:HeaderSize], crc)
	return buf, nil
}

// Parse decodes a full HeaderSize buffer. Wrong magic → ErrNotContainer;
// other failures → ErrCorruptHeader (wrapped).
func Parse(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: short header (%d bytes)", ErrCorruptHeader, len(b))
	}
	if string(b[0:8]) != Magic {
		return Header{}, ErrNotContainer
	}
	ver := b[8]
	if ver != VersionV1 {
		return Header{}, fmt.Errorf("%w: unsupported version %d", ErrCorruptHeader, ver)
	}
	total := binary.BigEndian.Uint16(b[10:12])
	if total != HeaderSize {
		return Header{}, fmt.Errorf("%w: header_total %d want %d", ErrCorruptHeader, total, HeaderSize)
	}
	wantCRC := binary.BigEndian.Uint32(b[crcOffset:HeaderSize])
	gotCRC := crc32.ChecksumIEEE(b[0:crcOffset])
	if wantCRC != gotCRC {
		return Header{}, fmt.Errorf("%w: crc mismatch", ErrCorruptHeader)
	}

	h := Header{
		Version:       ver,
		Flags:         b[9],
		PlaintextSize: int64(binary.BigEndian.Uint64(b[12:20])),
		SHA256:        append([]byte(nil), b[20:52]...),
		Enc:           b[52],
		Wrap:          b[53],
	}
	switch h.Enc {
	case EncNone, EncNative, EncCommand:
	default:
		return Header{}, fmt.Errorf("%w: unknown enc %d", ErrCorruptHeader, h.Enc)
	}
	switch h.Wrap {
	case WrapNone, WrapRSA, WrapKEK:
	default:
		return Header{}, fmt.Errorf("%w: unknown wrap %d", ErrCorruptHeader, h.Wrap)
	}
	tpLen := b[54]
	switch tpLen {
	case 0:
		// ok
	case thumbprintLen:
		h.Thumbprint = append([]byte(nil), b[56:76]...)
	default:
		return Header{}, fmt.Errorf("%w: bad thumbprint len %d", ErrCorruptHeader, tpLen)
	}
	provLen := b[55]
	if int(provLen) > providerMax {
		return Header{}, fmt.Errorf("%w: bad provider len %d", ErrCorruptHeader, provLen)
	}
	if provLen > 0 {
		h.Provider = string(b[84 : 84+provLen])
	}
	mtime := int64(binary.BigEndian.Uint64(b[76:84]))
	if mtime != 0 {
		h.SourceMTime = time.Unix(mtime, 0).UTC()
	}
	return h, nil
}

func encodeProvider(name string) (padded []byte, length uint8, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return make([]byte, providerMax), 0, nil
	}
	if len(name) > providerMax {
		return nil, 0, fmt.Errorf("container: provider longer than %d bytes", providerMax)
	}
	for _, r := range name {
		if r > unicode.MaxASCII || (!unicode.IsPrint(r) && !unicode.IsSpace(r)) {
			return nil, 0, fmt.Errorf("container: provider must be printable ASCII")
		}
	}
	padded = make([]byte, providerMax)
	copy(padded, name)
	return padded, uint8(len(name)), nil
}

// IsMagic reports whether b starts with the container magic (needs len >= 8).
func IsMagic(b []byte) bool {
	return len(b) >= len(Magic) && string(b[:len(Magic)]) == Magic
}

// EncFromName maps encryptor Name() to the wire enc byte.
func EncFromName(name string) uint8 {
	switch name {
	case "native":
		return EncNative
	case "command":
		return EncCommand
	default:
		return EncNone
	}
}

// EncName returns the string form used in ObjectMeta.Encrypted.
func EncName(enc uint8) string {
	switch enc {
	case EncNative:
		return "native"
	case EncCommand:
		return "command"
	default:
		return "none"
	}
}

// WrapFromName maps native wrap config / JSON names to the wire wrap byte.
func WrapFromName(name string) uint8 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "rsa-oaep", "rsa-oaep-256":
		return WrapRSA
	case "keyfile", "kek-aes-gcm":
		return WrapKEK
	default:
		return WrapNone
	}
}

// WrapName returns a stable string for ObjectMeta.Wrap / logs.
func WrapName(wrap uint8) string {
	switch wrap {
	case WrapRSA:
		return "rsa-oaep"
	case WrapKEK:
		return "keyfile"
	default:
		return ""
	}
}

// SHA256Hex returns the lowercase hex digest, or "" if SHA256 is wrong length.
func (h Header) SHA256Hex() string {
	if len(h.SHA256) != sha256Len {
		return ""
	}
	return hex.EncodeToString(h.SHA256)
}

// ThumbprintHex returns lowercase hex SHA-1, or "".
func (h Header) ThumbprintHex() string {
	if len(h.Thumbprint) != thumbprintLen {
		return ""
	}
	return hex.EncodeToString(h.Thumbprint)
}

// SHA256FromHex decodes a 64-char hex SHA-256 into 32 raw bytes.
func SHA256FromHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("container sha256: %w", err)
	}
	if len(b) != sha256Len {
		return nil, fmt.Errorf("container sha256: want %d bytes, got %d", sha256Len, len(b))
	}
	return b, nil
}

// ThumbprintFromHex decodes a 40-char hex SHA-1 into 20 raw bytes.
func ThumbprintFromHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("container thumbprint: %w", err)
	}
	if len(b) != thumbprintLen {
		return nil, fmt.Errorf("container thumbprint: want %d bytes, got %d", thumbprintLen, len(b))
	}
	return b, nil
}
