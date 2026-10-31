// Package s3target stores and validates a gateway user's optional destination
// S3 storage, and resolves it to an ObjectStore.
package s3target

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
)

// MaxProfileBytes bounds a --s3-profile file or stdin document. A target is a
// handful of short fields; anything larger is a mistake, not a configuration.
const MaxProfileBytes = 64 << 10

const defaultRegion = "us-east-1"

// profileJSON is the operator-facing --s3-profile document. SecretKey and
// SessionToken may appear only here: they are sealed into dedicated columns and
// never stored in the s3_target jsonb.
type profileJSON struct {
	Endpoint     string      `json:"endpoint"`
	Region       string      `json:"region"`
	Bucket       string      `json:"bucket"`
	Prefix       string      `json:"prefix"`
	PathStyle    bool        `json:"path_style"`
	AccessKey    string      `json:"access_key"`
	SecretKey    string      `json:"secret_key"`
	SessionToken string      `json:"session_token"`
	SSEKMS       *sseKMSJSON `json:"sse_kms,omitempty"`
	StorageClass string      `json:"storage_class,omitempty"`
}

// sseKMSJSON turns on SSE-KMS on the destination. Its presence is the switch:
// without it, no server-side-encryption headers are sent at all.
type sseKMSJSON struct {
	KeyID     string            `json:"key_id,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	BucketKey bool              `json:"bucket_key,omitempty"`
}

// storedJSON is the non-secret part kept in s3vault_users.s3_target.
type storedJSON struct {
	Endpoint     string      `json:"endpoint,omitempty"`
	Region       string      `json:"region"`
	Bucket       string      `json:"bucket"`
	Prefix       string      `json:"prefix,omitempty"`
	PathStyle    bool        `json:"path_style"`
	AccessKey    string      `json:"access_key"`
	SSEKMS       *sseKMSJSON `json:"sse_kms,omitempty"`
	StorageClass string      `json:"storage_class,omitempty"`
}

// Decode parses a full operator profile, including secrets.
func Decode(raw []byte) (port.S3Target, error) {
	var p profileJSON

	if err := decodeStrict(raw, &p); err != nil {
		return port.S3Target{}, err
	}

	return build(p, true)
}

// DecodeStored parses the non-secret jsonb column. secret_key and
// session_token are rejected as unknown fields: the database constraint forbids
// them there, and a stray copy must never be trusted.
func DecodeStored(raw []byte) (port.S3Target, error) {
	var p storedJSON

	if err := decodeStrict(raw, &p); err != nil {
		return port.S3Target{}, err
	}

	// The stored value must already be canonical: normalisation happens once in
	// Decode at add/update time, and Lookup only re-validates the row.
	return validateFields(profileJSON{
		Endpoint:     p.Endpoint,
		Region:       p.Region,
		Bucket:       p.Bucket,
		Prefix:       p.Prefix,
		PathStyle:    p.PathStyle,
		AccessKey:    p.AccessKey,
		SSEKMS:       p.SSEKMS,
		StorageClass: p.StorageClass,
	}, false, true)
}

// StoredJSON encodes the non-secret part of a validated target for the jsonb
// column.
func StoredJSON(t port.S3Target) ([]byte, error) {
	if err := Validate(t); err != nil {
		return nil, err
	}

	//nolint:gosec // G117: access_key is an identifier, not a secret; secret_key/session_token are never in this struct.
	return json.Marshal(storedJSON{
		Endpoint:     t.Endpoint,
		Region:       t.Region,
		Bucket:       t.Bucket,
		Prefix:       t.Prefix,
		PathStyle:    t.PathStyle,
		AccessKey:    t.AccessKey,
		SSEKMS:       sseKMSStored(t.SSEKMS),
		StorageClass: t.StorageClass,
	})
}

// Validate re-checks a target that was already decoded (or assembled from the
// database). It never rewrites the value: a non-canonical endpoint or prefix is
// an error, not something to silently normalise on every request.
func Validate(t port.S3Target) error {
	_, err := validateFields(profileJSON{
		Endpoint:     t.Endpoint,
		Region:       t.Region,
		Bucket:       t.Bucket,
		Prefix:       t.Prefix,
		PathStyle:    t.PathStyle,
		AccessKey:    t.AccessKey,
		SecretKey:    t.SecretKey,
		SessionToken: t.SessionToken,
		SSEKMS:       sseKMSStored(t.SSEKMS),
		StorageClass: t.StorageClass,
	}, true, true)

	return err
}

func build(p profileJSON, requireSecrets bool) (port.S3Target, error) {
	return validateFields(p, requireSecrets, false)
}

//nolint:gocyclo // one validation function keeps every target field's rule in one place.
func validateFields(p profileJSON, requireSecrets, canonical bool) (port.S3Target, error) {
	endpoint, err := normalizeEndpoint(p.Endpoint)
	if err != nil {
		return port.S3Target{}, err
	}

	if canonical && endpoint != p.Endpoint {
		return port.S3Target{}, fmt.Errorf("s3target: endpoint %q is not canonical (want %q)", p.Endpoint, endpoint)
	}

	region := strings.TrimSpace(p.Region)
	if region == "" {
		region = defaultRegion
	}

	if err := validPlainField("region", region, 1, 64); err != nil {
		return port.S3Target{}, err
	}

	bucket := p.Bucket
	if err := validBucket(bucket); err != nil {
		return port.S3Target{}, err
	}

	prefix, err := keying.NormalizeOptionalPrefix(p.Prefix)
	if err != nil {
		return port.S3Target{}, fmt.Errorf("s3target: prefix: %w", err)
	}

	if canonical && prefix != p.Prefix {
		return port.S3Target{}, fmt.Errorf("s3target: prefix %q is not canonical (want %q)", p.Prefix, prefix)
	}

	if err := validAccessKey(p.AccessKey); err != nil {
		return port.S3Target{}, err
	}

	storageClass, err := normalizeStorageClass(p.StorageClass)
	if err != nil {
		return port.S3Target{}, err
	}

	if canonical && storageClass != p.StorageClass {
		return port.S3Target{}, fmt.Errorf("s3target: storage_class %q is not canonical (want %q)", p.StorageClass, storageClass)
	}

	sse, err := buildSSEKMS(p.SSEKMS)
	if err != nil {
		return port.S3Target{}, err
	}

	t := port.S3Target{
		Endpoint:     endpoint,
		Region:       region,
		Bucket:       bucket,
		Prefix:       prefix,
		PathStyle:    p.PathStyle,
		AccessKey:    p.AccessKey,
		SSEKMS:       sse,
		StorageClass: storageClass,
	}

	if requireSecrets {
		if err := validSecret(p.SecretKey); err != nil {
			return port.S3Target{}, err
		}

		if err := validSessionToken(p.SessionToken); err != nil {
			return port.S3Target{}, err
		}

		t.SecretKey = p.SecretKey
		t.SessionToken = p.SessionToken
	}

	return t, nil
}

func decodeStrict(raw []byte, dst any) error {
	if len(raw) > MaxProfileBytes {
		return fmt.Errorf("s3target: profile is %d bytes, over the %d byte limit", len(raw), MaxProfileBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("s3target: parse profile: %w", err)
	}

	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("s3target: profile has trailing JSON")
		}

		return fmt.Errorf("s3target: trailing data: %w", err)
	}

	return nil
}

func normalizeEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("s3target: endpoint: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("s3target: endpoint %q: scheme must be http or https", raw)
	}

	if u.Host == "" {
		return "", fmt.Errorf("s3target: endpoint %q: host is required", raw)
	}

	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("s3target: endpoint %q: userinfo, query and fragment are not allowed", raw)
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""

	return u.String(), nil
}

func validBucket(bucket string) error {
	if bucket == "" {
		return errors.New("s3target: bucket is required")
	}

	if len(bucket) > 255 {
		return fmt.Errorf("s3target: bucket is %d bytes, over the 255 byte limit", len(bucket))
	}

	if strings.TrimSpace(bucket) != bucket {
		return errors.New("s3target: bucket has leading or trailing whitespace")
	}

	for _, r := range bucket {
		if r == '/' || r == '\\' || r == 0 || r < ' ' || r == 0x7f {
			return fmt.Errorf("s3target: bucket %q contains a forbidden character", bucket)
		}
	}

	return nil
}

func validAccessKey(key string) error {
	if key == "" {
		return errors.New("s3target: access_key is required")
	}

	if err := validPlainField("access_key", key, 1, 128); err != nil {
		return err
	}

	return nil
}

func validSecret(secret string) error {
	if secret == "" {
		return errors.New("s3target: secret_key is required")
	}

	if len(secret) > 512 {
		return fmt.Errorf("s3target: secret_key is %d bytes, over the 512 byte limit", len(secret))
	}

	if strings.ContainsRune(secret, 0) {
		return errors.New("s3target: secret_key contains NUL")
	}

	return nil
}

func validSessionToken(token string) error {
	if len(token) > 4096 {
		return fmt.Errorf("s3target: session_token is %d bytes, over the 4096 byte limit", len(token))
	}

	if strings.ContainsRune(token, 0) {
		return errors.New("s3target: session_token contains NUL")
	}

	return nil
}

// normalizeStorageClass accepts any non-empty printable value. S3-compatible
// providers expose custom classes (for example ICE or COLD), so the gateway
// must not restrict the value to AWS's enum. The value is sent verbatim; an
// empty value means "do not send x-amz-storage-class".
func normalizeStorageClass(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}

	if err := validPlainField("storage_class", trimmed, 1, 64); err != nil {
		return "", err
	}

	return trimmed, nil
}

// buildSSEKMS converts the profile's sse_kms object to the port type, or nil
// when it is absent. An empty object is not absent: it means "use the bucket's
// default KMS key", which is exactly what SSE-KMS does without a key id.
func buildSSEKMS(p *sseKMSJSON) (*port.SSEKMS, error) {
	if p == nil {
		return nil, nil
	}

	if p.KeyID != "" {
		if err := validPlainField("sse_kms.key_id", p.KeyID, 1, 2048); err != nil {
			return nil, err
		}
	}

	if len(p.Context) > 64 {
		return nil, fmt.Errorf("s3target: sse_kms.context has %d entries, over the 64 entry limit", len(p.Context))
	}

	total := 0

	for k, v := range p.Context {
		if k == "" || len(k) > 256 {
			return nil, fmt.Errorf("s3target: sse_kms.context key must be 1..256 bytes, got %d", len(k))
		}

		if len(v) > 1024 {
			return nil, fmt.Errorf("s3target: sse_kms.context value for %q is %d bytes, over the 1024 byte limit", k, len(v))
		}

		if strings.ContainsRune(k, 0) || strings.ContainsRune(v, 0) {
			return nil, errors.New("s3target: sse_kms.context contains NUL")
		}

		total += len(k) + len(v)
	}

	if total > 8192 {
		return nil, fmt.Errorf("s3target: sse_kms.context is %d bytes, over the 8192 byte limit", total)
	}

	context := make(map[string]string, len(p.Context))
	maps.Copy(context, p.Context)

	return &port.SSEKMS{KeyID: p.KeyID, Context: context, BucketKey: p.BucketKey}, nil
}

func sseKMSStored(sse *port.SSEKMS) *sseKMSJSON {
	if sse == nil {
		return nil
	}

	context := make(map[string]string, len(sse.Context))
	maps.Copy(context, sse.Context)

	return &sseKMSJSON{KeyID: sse.KeyID, Context: context, BucketKey: sse.BucketKey}
}

func validPlainField(name, value string, minLen, maxLen int) error {
	if len(value) < minLen || len(value) > maxLen {
		return fmt.Errorf("s3target: %s must be %d..%d bytes, got %d", name, minLen, maxLen, len(value))
	}

	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("s3target: %s contains whitespace or control characters", name)
		}
	}

	return nil
}

// Namespace identifies where a target's data lives, ignoring secrets. It names
// cache and ephemeral keys and is safe to log.
func Namespace(t port.S3Target) string {
	return canonicalDigest(t, false)
}

// Fingerprint identifies the full target including secret hashes. It is the
// pool key and the multipart snapshot value; it never reaches a log or a client.
func Fingerprint(t port.S3Target) string {
	return canonicalDigest(t, true)
}

func canonicalDigest(t port.S3Target, withSecrets bool) string {
	h := sha256.New()
	writeField(h, "s3target:v1")
	writeField(h, t.Endpoint)
	writeField(h, t.Region)
	writeField(h, t.Bucket)
	writeField(h, t.Prefix)
	writeField(h, strconv.FormatBool(t.PathStyle))
	writeField(h, t.AccessKey)

	if withSecrets {
		writeField(h, secretDigest(t.SecretKey))
		writeField(h, secretDigest(t.SessionToken))
		// Write-side options do not move the data, so they stay out of the
		// cache namespace, but they do change what the pooled store sends.
		writeField(h, t.StorageClass)

		if t.SSEKMS == nil {
			writeField(h, "")
		} else {
			writeField(h, "sse-kms")
			writeField(h, t.SSEKMS.KeyID)

			keys := slices.Sorted(maps.Keys(t.SSEKMS.Context))
			writeField(h, strconv.Itoa(len(keys)))

			for _, k := range keys {
				writeField(h, k)
				writeField(h, t.SSEKMS.Context[k])
			}

			writeField(h, strconv.FormatBool(t.SSEKMS.BucketKey))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// writeField writes a length-prefixed value, so field boundaries cannot be
// forged with a value that contains the separator.
func writeField(h hash.Hash, value string) {
	_, _ = io.WriteString(h, strconv.Itoa(len(value)))
	_, _ = io.WriteString(h, ":")
	_, _ = io.WriteString(h, value)
	_, _ = io.WriteString(h, ";")
}

func secretDigest(secret string) string {
	if secret == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(secret))

	return hex.EncodeToString(sum[:])
}
