package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	postgresauth "github.com/xMlex/s3vault/internal/adapter/s3auth/postgres"
	"github.com/xMlex/s3vault/internal/port"
)

const testTargetBucket = "archive"

func TestReadEncryption(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		got, err := readEncryption(strings.NewReader(""), "")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("stdin", func(t *testing.T) {
		t.Parallel()

		got, err := readEncryption(strings.NewReader(`{"mode":"none"}`), "-")
		require.NoError(t, err)
		assert.JSONEq(t, `{"mode":"none"}`, string(got))
	})

	t.Run("empty object", func(t *testing.T) {
		t.Parallel()

		got, err := readEncryption(strings.NewReader(`{}`), "-")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "profile.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"mode":"none"}`), 0o600))

		got, err := readEncryption(strings.NewReader(""), path)
		require.NoError(t, err)
		assert.JSONEq(t, `{"mode":"none"}`, string(got))
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()

		_, err := readEncryption(strings.NewReader("not json"), "-")
		require.Error(t, err)
	})
}

func TestProfileMode(t *testing.T) {
	t.Parallel()

	assert.Equal(t, labelGlobal, profileMode(nil))
	assert.Equal(t, labelGlobal, profileMode([]byte(`{"mode":""}`)))
	assert.Equal(t, "native", profileMode([]byte(`{"mode":"native"}`)))
	assert.Equal(t, "invalid", profileMode([]byte(`not json`)))
}

func TestReadS3Profile(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		got, err := readS3Profile(strings.NewReader(""), "")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("stdin", func(t *testing.T) {
		t.Parallel()

		got, err := readS3Profile(strings.NewReader(`{
			"bucket": "`+testTargetBucket+`",
			"access_key": "AKIA",
			"secret_key": "secret"
		}`), "-")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, testTargetBucket, got.Bucket)
		assert.Equal(t, "AKIA", got.AccessKey)
	})

	t.Run("file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "target.json")
		require.NoError(t, os.WriteFile(path, []byte(`{
			"bucket": "`+testTargetBucket+`",
			"access_key": "AKIA",
			"secret_key": "secret"
		}`), 0o600))

		got, err := readS3Profile(strings.NewReader(""), path)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, testTargetBucket, got.Bucket)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()

		_, err := readS3Profile(strings.NewReader(`{"bucket":"`+testTargetBucket+`"}`), "-")
		require.Error(t, err)
	})
}

func TestS3TargetLabel(t *testing.T) {
	t.Parallel()

	assert.Equal(t, labelGlobal, s3TargetLabel(nil))
	assert.Equal(t, "aws/"+testTargetBucket, s3TargetLabel(&postgresauth.TargetInfo{Bucket: testTargetBucket}))
	assert.Equal(t, "https://s3.example.com/"+testTargetBucket, s3TargetLabel(&postgresauth.TargetInfo{
		Endpoint: "https://s3.example.com",
		Bucket:   testTargetBucket,
	}))
}

func TestWriteUsersJSONHidesTargetSecrets(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	require.NoError(t, writeUsersJSON(&out, []postgresauth.User{{
		ID:          1,
		Name:        "alice",
		AccessKeyID: "S3VFRONTEND",
		Prefix:      "tenant-a",
		EncryptionProfile: &postgresauth.EncryptionProfileRef{
			UID:    "profile-uid",
			Name:   "shared-native",
			Config: json.RawMessage(`{"mode":"native"}`),
		},
		Target: &postgresauth.TargetInfo{
			UID:          "target-uid",
			Name:         "archive",
			Endpoint:     "https://s3.example.com",
			Region:       "us-east-1",
			Bucket:       testTargetBucket,
			Prefix:       "vault",
			PathStyle:    true,
			AccessKey:    "AKIATARGET",
			SSEKMS:       &port.SSEKMS{KeyID: "alias/vault", Context: map[string]string{"tenant": "alice"}, BucketKey: true},
			StorageClass: "STANDARD_IA",
		},
	}}))

	body := out.String()
	assert.Contains(t, body, `"encryption_profile"`)
	assert.Contains(t, body, `"name": "shared-native"`)
	assert.Contains(t, body, `"mode": "native"`)
	assert.Contains(t, body, `"s3_target"`)
	assert.Contains(t, body, `"name": "archive"`)
	assert.Contains(t, body, `"uid": "target-uid"`)
	assert.Contains(t, body, `"bucket": "`+testTargetBucket+`"`)
	assert.Contains(t, body, `"storage_class": "STANDARD_IA"`)
	assert.Contains(t, body, `"sse_kms"`)
	assert.Contains(t, body, `"key_id": "alias/vault"`)
	assert.NotContains(t, body, "secret_key")
	assert.NotContains(t, body, "session_token")
	assert.NotContains(t, body, "AKIATARGET")

	var decoded []map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	require.Len(t, decoded, 1)
	assert.NotNil(t, decoded[0]["s3_target"])

	// A user without a target or profile renders both as null, not empty objects.
	out.Reset()
	require.NoError(t, writeUsersJSON(&out, []postgresauth.User{{ID: 2, AccessKeyID: "S3VOTHER"}}))
	assert.Contains(t, out.String(), `"s3_target": null`)
	assert.Contains(t, out.String(), `"encryption_profile": null`)
}
