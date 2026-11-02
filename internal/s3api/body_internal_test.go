package s3api

import (
	"net/http"
	"testing"

	"github.com/amwolff/awsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrailerAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want awsig.ChecksumAlgorithm
		ok   bool
	}{
		{name: "crc32", raw: "x-amz-checksum-crc32", want: awsig.AlgorithmCRC32, ok: true},
		{name: "crc32c", raw: "x-amz-checksum-crc32c", want: awsig.AlgorithmCRC32C, ok: true},
		{name: "crc64nvme", raw: "x-amz-checksum-crc64nvme", want: awsig.AlgorithmCRC64NVME, ok: true},
		{name: "sha1", raw: "x-amz-checksum-sha1", want: awsig.AlgorithmSHA1, ok: true},
		{name: "sha256", raw: "x-amz-checksum-sha256", want: awsig.AlgorithmSHA256, ok: true},
		{name: "uppercase", raw: "X-Amz-Checksum-CRC32", want: awsig.AlgorithmCRC32, ok: true},
		{name: "list picks a supported name", raw: "x-amz-checksum-sha512, x-amz-checksum-crc32", want: awsig.AlgorithmCRC32, ok: true},
		{name: "unsupported", raw: "x-amz-checksum-sha512"},
		{name: "not a checksum", raw: "x-amz-meta-note"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := trailerAlgorithm(tc.raw)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTrailingChecksumRequestFallsBackToSDKAlgorithm(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set(headerXAmzSDKChecksumAlgorithm, "CRC32")

	_, err := trailingChecksumRequest(h)
	require.NoError(t, err)
}

func TestTrailingChecksumRequestRejectsUnsupportedTrailer(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set(headerXAmzTrailer, "x-amz-checksum-sha512")

	_, err := trailingChecksumRequest(h)
	require.ErrorIs(t, err, errUnsupportedTrailingChecksum)
}

func TestTrailingChecksumRequestNeedsAnAlgorithm(t *testing.T) {
	t.Parallel()

	_, err := trailingChecksumRequest(http.Header{})
	require.ErrorIs(t, err, errMissingTrailingChecksum)
}

func TestIsTrailingPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "unsigned trailer", header: "STREAMING-UNSIGNED-PAYLOAD-TRAILER", want: true},
		{name: "signed trailer", header: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", want: true},
		{name: "signed without trailer", header: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		{name: "ordinary payload", header: "UNSIGNED-PAYLOAD"},
		{name: "empty"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := http.NewRequestWithContext(t.Context(), http.MethodPut, "http://example.test/k", nil)
			require.NoError(t, err)

			if tc.header != "" {
				r.Header.Set(headerXAmzContentSHA256, tc.header)
			}

			assert.Equal(t, tc.want, isTrailingPayload(r))
		})
	}
}
