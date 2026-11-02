package s3api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client that streams the body and puts the checksum in an aws-chunked
// trailer (AWS CLI v2, CRT uploaders) must be able to PutObject. The gateway
// used to answer 403 here: awsig was handed no trailing algorithm, although the
// algorithm is named in x-amz-trailer, and it refused to decode the framing.
func TestPutWithTrailingChecksum(t *testing.T) {
	t.Parallel()

	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	payload := []byte("payload with a trailing crc32")
	resp := doSignedTrailerPut(t, srv.URL+"/vault/streamed.txt", payload, crc32Base64(payload))

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	got := readObject(t, newS3Client(srv.URL, mpAccessKey, mpSecretKey), "streamed.txt")
	assert.Equal(t, payload, got)
}

func TestUploadPartWithTrailingChecksum(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)
	uploadID := createMultipart(t, f.client, "trail.bin")

	payload := []byte("multipart part with a trailing crc32")
	req := signedTrailerRequest(t, http.MethodPut, uploadPartURL(t, f.baseURL, uploadID, 1), payload, crc32Base64(payload))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag)

	_, err = f.client.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(mpBucket),
		Key:      aws.String("trail.bin"),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: aws.String(etag), PartNumber: aws.Int32(1)}},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, payload, readObject(t, f.client, "trail.bin"))
}

func TestPutWithTrailingChecksumMismatch(t *testing.T) {
	t.Parallel()

	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	payload := []byte("payload with a wrong crc32")
	resp := doSignedTrailerPut(t, srv.URL+"/vault/bad.txt", payload, crc32Base64([]byte("something else")))

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
	assert.Contains(t, string(body), "<Code>BadDigest</Code>")
}

// doSignedTrailerPut builds and signs STREAMING-UNSIGNED-PAYLOAD-TRAILER, the
// exact shape a CRT client sends: aws-chunked framing, the checksum after the
// last chunk, and x-amz-trailer naming it.
func doSignedTrailerPut(t *testing.T, endpoint string, payload []byte, checksum string) *http.Response {
	t.Helper()

	resp, err := http.DefaultClient.Do(signedTrailerRequest(t, http.MethodPut, endpoint, payload, checksum))
	require.NoError(t, err)

	return resp
}

func signedTrailerRequest(t *testing.T, method, endpoint string, payload []byte, checksum string) *http.Request {
	t.Helper()

	framed := []byte(strconv.FormatInt(int64(len(payload)), 16) + "\r\n")
	framed = append(framed, payload...)
	framed = append(framed, "\r\n0\r\nx-amz-checksum-crc32:"+checksum+"\r\n\r\n"...)

	req, err := http.NewRequestWithContext(context.Background(), method, endpoint, bytes.NewReader(framed))
	require.NoError(t, err)

	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(payload)))
	req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")

	require.NoError(t, v4.NewSigner().SignHTTP(
		context.Background(),
		aws.Credentials{AccessKeyID: mpAccessKey, SecretAccessKey: mpSecretKey},
		req,
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		"s3",
		"us-east-1",
		time.Now(),
	))

	return req
}

func uploadPartURL(t *testing.T, base, uploadID string, number int) string {
	t.Helper()

	u, err := url.Parse(base + "/" + mpBucket + "/trail.bin")
	require.NoError(t, err)

	q := u.Query()
	q.Set("partNumber", strconv.Itoa(number))
	q.Set("uploadId", uploadID)
	u.RawQuery = q.Encode()

	return u.String()
}

func crc32Base64(payload []byte) string {
	var sum [4]byte

	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE(payload))

	return base64.StdEncoding.EncodeToString(sum[:])
}
