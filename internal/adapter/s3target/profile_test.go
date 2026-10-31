package s3target

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/port"
)

func fullProfile() []byte {
	return []byte(`{
		"endpoint": "https://s3.example.com/",
		"region": "eu-central-1",
		"bucket": "archive",
		"prefix": "vault",
		"path_style": true,
		"access_key": "AKIAEXAMPLE",
		"secret_key": "top-secret",
		"session_token": "session"
	}`)
}

func TestDecodeNormalizes(t *testing.T) {
	t.Parallel()

	target, err := Decode([]byte(`{
		"endpoint": "  HTTPS://S3.Example.COM/  ",
		"bucket": "archive",
		"prefix": " /tenant/logs/ ",
		"access_key": "AKIAEXAMPLE",
		"secret_key": "top-secret"
	}`))
	require.NoError(t, err)

	assert.Equal(t, "https://s3.example.com", target.Endpoint)
	assert.Equal(t, "us-east-1", target.Region)
	assert.Equal(t, "tenant/logs", target.Prefix)
	assert.False(t, target.PathStyle)
	assert.Equal(t, "top-secret", target.SecretKey)
}

func TestDecodeDefaultsAndFullProfile(t *testing.T) {
	t.Parallel()

	target, err := Decode(fullProfile())
	require.NoError(t, err)

	assert.Equal(t, port.S3Target{
		Endpoint:     "https://s3.example.com",
		Region:       "eu-central-1",
		Bucket:       "archive",
		Prefix:       "vault",
		PathStyle:    true,
		AccessKey:    "AKIAEXAMPLE",
		SecretKey:    "top-secret",
		SessionToken: "session",
	}, target)
}

func TestDecodeRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "unknown field", raw: `{"bucket":"b","access_key":"a","secret_key":"s","multipart_part_size":5}`, want: "unknown field"},
		{name: "trailing json", raw: `{"bucket":"b","access_key":"a","secret_key":"s"} {}`, want: "trailing"},
		{name: "missing secret", raw: `{"bucket":"b","access_key":"a"}`, want: "secret_key"},
		{name: "missing access key", raw: `{"bucket":"b","secret_key":"s"}`, want: "access_key"},
		{name: "missing bucket", raw: `{"access_key":"a","secret_key":"s"}`, want: "bucket"},
		{name: "bucket slash", raw: `{"bucket":"a/b","access_key":"a","secret_key":"s"}`, want: "forbidden"},
		{name: "endpoint query", raw: `{"endpoint":"https://x/y?z=1","bucket":"b","access_key":"a","secret_key":"s"}`, want: "query"},
		{name: "endpoint userinfo", raw: `{"endpoint":"https://u@x","bucket":"b","access_key":"a","secret_key":"s"}`, want: "userinfo"},
		{name: "endpoint scheme", raw: `{"endpoint":"ftp://x","bucket":"b","access_key":"a","secret_key":"s"}`, want: "scheme"},
		{name: "traversal prefix", raw: `{"bucket":"b","prefix":"a/../b","access_key":"a","secret_key":"s"}`, want: "prefix"},
		{name: "nul secret", raw: `{"bucket":"b","access_key":"a","secret_key":"s\u0000"}`, want: "NUL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Decode([]byte(tt.raw))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestDecodeTooLarge(t *testing.T) {
	t.Parallel()

	raw := `{"bucket":"b","access_key":"a","secret_key":"s","padding":"` + strings.Repeat("x", MaxProfileBytes) + `"}`
	_, err := Decode([]byte(raw))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "over the")
}

func TestDecodeStored(t *testing.T) {
	t.Parallel()

	stored := []byte(`{
		"endpoint": "https://s3.example.com",
		"region": "eu-central-1",
		"bucket": "archive",
		"prefix": "vault",
		"path_style": true,
		"access_key": "AKIAEXAMPLE"
	}`)

	target, err := DecodeStored(stored)
	require.NoError(t, err)
	assert.Empty(t, target.SecretKey)
	assert.Empty(t, target.SessionToken)

	_, err = DecodeStored([]byte(`{"bucket":"b","access_key":"a","secret_key":"s"}`))
	require.Error(t, err)

	_, err = DecodeStored([]byte(`{"endpoint":"https://S3.Example.COM","bucket":"b","access_key":"a"}`))
	require.Error(t, err, "a stored endpoint must already be canonical")
}

func TestStoredJSONRoundTrip(t *testing.T) {
	t.Parallel()

	target, err := Decode(fullProfile())
	require.NoError(t, err)

	raw, err := StoredJSON(target)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "secret_key")
	assert.NotContains(t, string(raw), "session_token")
	assert.NotContains(t, string(raw), "top-secret")

	stored, err := DecodeStored(raw)
	require.NoError(t, err)
	assert.Equal(t, target.Endpoint, stored.Endpoint)
	assert.Equal(t, target.Region, stored.Region)
	assert.Equal(t, target.Bucket, stored.Bucket)
	assert.Equal(t, target.Prefix, stored.Prefix)
	assert.Equal(t, target.PathStyle, stored.PathStyle)
	assert.Equal(t, target.AccessKey, stored.AccessKey)
}

func TestNamespaceAndFingerprint(t *testing.T) {
	t.Parallel()

	base, err := Decode(fullProfile())
	require.NoError(t, err)

	rotated := base
	rotated.SecretKey = "another-secret"

	assert.NotEqual(t, Fingerprint(base), Fingerprint(rotated), "a secret rotation must change the fingerprint")
	assert.Equal(t, Namespace(base), Namespace(rotated), "a secret rotation must not invalidate the cache namespace")

	otherAccount := base
	otherAccount.AccessKey = "AKIAOTHER"
	assert.NotEqual(t, Namespace(base), Namespace(otherAccount), "the access key distinguishes accounts on one endpoint")

	otherBucket := base
	otherBucket.Bucket = "other"
	assert.NotEqual(t, Namespace(base), Namespace(otherBucket))

	assert.Len(t, Namespace(base), 64)
	assert.Len(t, Fingerprint(base), 64)
}

func TestValidateRejectsNonCanonical(t *testing.T) {
	t.Parallel()

	target, err := Decode(fullProfile())
	require.NoError(t, err)
	require.NoError(t, Validate(target))

	bad := target
	bad.Endpoint = "https://s3.example.com/"
	require.Error(t, Validate(bad))

	bad = target
	bad.Prefix = "/vault/"
	require.Error(t, Validate(bad))

	bad = target
	bad.SecretKey = ""
	require.Error(t, Validate(bad))
}

func TestDecodeSSEKMSAndStorageClass(t *testing.T) {
	t.Parallel()

	target, err := Decode([]byte(`{
		"bucket": "archive",
		"access_key": "AKIA",
		"secret_key": "secret",
		"storage_class": " standard_ia ",
		"sse_kms": {
			"key_id": "arn:aws:kms:eu-central-1:123456789012:key/abc",
			"context": {"tenant": "alice"},
			"bucket_key": true
		}
	}`))
	require.NoError(t, err)

	require.NotNil(t, target.SSEKMS)
	assert.Equal(t, "arn:aws:kms:eu-central-1:123456789012:key/abc", target.SSEKMS.KeyID)
	assert.Equal(t, map[string]string{"tenant": "alice"}, target.SSEKMS.Context)
	assert.True(t, target.SSEKMS.BucketKey)
	assert.Equal(t, "standard_ia", target.StorageClass, "the operator's value is sent verbatim")

	// Arbitrary custom classes are valid and preserved; they are not limited to
	// AWS's enum.
	for _, class := range []string{"ICE", "COLD", "COLDLINE"} {
		custom, err := Decode([]byte(`{"bucket":"b","access_key":"a","secret_key":"s","storage_class":"` + class + `"}`))
		require.NoError(t, err)
		assert.Equal(t, class, custom.StorageClass)
	}

	// Empty sse_kms is present, not absent: it means "use the bucket's default
	// KMS key". Absent storage_class means "send no header".
	plain, err := Decode([]byte(`{"bucket":"b","access_key":"a","secret_key":"s"}`))
	require.NoError(t, err)
	assert.Nil(t, plain.SSEKMS)
	assert.Empty(t, plain.StorageClass)

	def, err := Decode([]byte(`{"bucket":"b","access_key":"a","secret_key":"s","sse_kms":{}}`))
	require.NoError(t, err)
	assert.NotNil(t, def.SSEKMS)
	assert.Empty(t, def.SSEKMS.KeyID)
}

func TestSSEKMSAndStorageClassValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "unknown nested field", raw: `{"bucket":"b","access_key":"a","secret_key":"s","sse_kms":{"unknown":1}}`, want: "unknown field"},
		{name: "storage class with space", raw: `{"bucket":"b","access_key":"a","secret_key":"s","storage_class":"A B"}`, want: "storage_class"},
		{name: "storage class too long", raw: `{"bucket":"b","access_key":"a","secret_key":"s","storage_class":"` + strings.Repeat("X", 65) + `"}`, want: "storage_class"},
		{name: "nul key id", raw: `{"bucket":"b","access_key":"a","secret_key":"s","sse_kms":{"key_id":"a\u0000b"}}`, want: "key_id"},
		{name: "nul context", raw: `{"bucket":"b","access_key":"a","secret_key":"s","sse_kms":{"context":{"k":"a\u0000b"}}}`, want: "NUL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Decode([]byte(tt.raw))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestSSEKMSAndStorageClassStored(t *testing.T) {
	t.Parallel()

	target, err := Decode([]byte(`{
		"bucket": "archive",
		"access_key": "AKIA",
		"secret_key": "secret",
		"storage_class": "GLACIER_IR",
		"sse_kms": {"key_id": "alias/vault", "context": {"tenant": "alice"}, "bucket_key": true}
	}`))
	require.NoError(t, err)

	raw, err := StoredJSON(target)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"sse_kms"`)
	assert.Contains(t, string(raw), `"storage_class":"GLACIER_IR"`)
	assert.NotContains(t, string(raw), "secret_key")

	stored, err := DecodeStored(raw)
	require.NoError(t, err)
	assert.Equal(t, target.SSEKMS, stored.SSEKMS)
	assert.Equal(t, target.StorageClass, stored.StorageClass)

	// Direct SQL with a non-canonical storage class fails at Lookup/startup.
	_, err = DecodeStored([]byte(`{"bucket":"b","access_key":"a","storage_class":" standard_ia "}`))
	require.Error(t, err)
}

func TestWriteOptionsAffectFingerprintNotNamespace(t *testing.T) {
	t.Parallel()

	base, err := Decode(fullProfile())
	require.NoError(t, err)

	sse := base
	sse.SSEKMS = &port.SSEKMS{KeyID: "alias/vault", BucketKey: true}

	class := base
	class.StorageClass = "STANDARD_IA"

	assert.NotEqual(t, Fingerprint(base), Fingerprint(sse))
	assert.NotEqual(t, Fingerprint(base), Fingerprint(class))
	assert.Equal(t, Namespace(base), Namespace(sse), "SSE changes how bytes are written, not where they live")
	assert.Equal(t, Namespace(base), Namespace(class), "storage class does not move the object")
}
