package s3api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/port"
)

const (
	headerXAmzContentSHA256        = "x-amz-content-sha256"
	headerXAmzTrailer              = "x-amz-trailer"
	headerXAmzSDKChecksumAlgorithm = "x-amz-sdk-checksum-algorithm"

	trailerChecksumPrefix = "x-amz-checksum-"
	trailerPayloadSuffix  = "-TRAILER"
)

var (
	errMissingTrailingChecksum     = errors.New("trailing payload without a checksum algorithm")
	errUnsupportedTrailingChecksum = errors.New("unsupported trailing checksum algorithm")
)

// requestBody returns the verified body of a request.
//
// A streaming body with a trailing checksum — x-amz-content-sha256:
// STREAMING-UNSIGNED-PAYLOAD-TRAILER or STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
// — cannot be decoded without naming the algorithm: the aws-chunked framing puts
// the digest after the payload, and awsig has to know which x-amz-checksum-* line
// to expect at the end. The sentinel in x-amz-content-sha256 names the framing,
// not the algorithm; clients put the latter in x-amz-trailer and/or
// x-amz-sdk-checksum-algorithm. AWS CLI v2 and other CRT-based clients send such
// requests even over plain HTTP, so treating them as ordinary bodies is not an
// option.
func requestBody(r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal]) (awsig.Reader, error) {
	if !isTrailingPayload(r) {
		return vr.Reader()
	}

	req, err := trailingChecksumRequest(r.Header)
	if err != nil {
		return nil, err
	}

	return vr.Reader(req)
}

func isTrailingPayload(r *http.Request) bool {
	return strings.HasSuffix(strings.TrimSpace(r.Header.Get(headerXAmzContentSHA256)), trailerPayloadSuffix)
}

func trailingChecksumRequest(h http.Header) (awsig.ChecksumRequest, error) {
	rawTrailer := h.Get(headerXAmzTrailer)
	if rawTrailer != "" {
		algorithm, ok := trailerAlgorithm(rawTrailer)
		if !ok {
			return awsig.ChecksumRequest{}, fmt.Errorf("%w: %q", errUnsupportedTrailingChecksum, rawTrailer)
		}

		return newTrailingChecksumRequest(algorithm)
	}

	algorithm, ok := checksumAlgorithmByName(h.Get(headerXAmzSDKChecksumAlgorithm))
	if !ok {
		return awsig.ChecksumRequest{}, errMissingTrailingChecksum
	}

	return newTrailingChecksumRequest(algorithm)
}

func newTrailingChecksumRequest(algorithm awsig.ChecksumAlgorithm) (awsig.ChecksumRequest, error) {
	req, err := awsig.NewTrailingChecksumRequest(algorithm)
	if err != nil {
		return awsig.ChecksumRequest{}, fmt.Errorf("%w: %w", errUnsupportedTrailingChecksum, err)
	}

	return req, nil
}

// trailerAlgorithm parses the comma-separated x-amz-trailer value. S3 allows a
// single trailing chunk, but the header is a list by grammar, so the first
// supported entry wins rather than rejecting a value another implementation
// padded with an extra name.
func trailerAlgorithm(raw string) (awsig.ChecksumAlgorithm, bool) {
	for name := range strings.SplitSeq(raw, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if !strings.HasPrefix(name, trailerChecksumPrefix) {
			continue
		}

		if algorithm, ok := checksumAlgorithmByName(strings.TrimPrefix(name, trailerChecksumPrefix)); ok {
			return algorithm, true
		}
	}

	return awsig.AlgorithmNone, false
}

func checksumAlgorithmByName(name string) (awsig.ChecksumAlgorithm, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "crc32":
		return awsig.AlgorithmCRC32, true
	case "crc32c":
		return awsig.AlgorithmCRC32C, true
	case "crc64nvme":
		return awsig.AlgorithmCRC64NVME, true
	case "md5":
		return awsig.AlgorithmMD5, true
	case "sha1":
		return awsig.AlgorithmSHA1, true
	case "sha256":
		return awsig.AlgorithmSHA256, true
	default:
		return awsig.AlgorithmNone, false
	}
}
