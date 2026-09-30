// Package s3err writes compact S3-compatible XML error responses.
// Error catalog shape is inspired by SeaweedFS weed/s3api/s3err (Apache-2.0).
package s3err

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"net/http"
)

// Code is an S3 error code string.
type Code string

const (
	AccessDenied          Code = "AccessDenied"
	NoSuchKey             Code = "NoSuchKey"
	NoSuchBucket          Code = "NoSuchBucket"
	InvalidBucketName     Code = "InvalidBucketName"
	InternalError         Code = "InternalError"
	SignatureDoesNotMatch Code = "SignatureDoesNotMatch"
	InvalidAccessKeyId    Code = "InvalidAccessKeyId"
	MethodNotAllowed      Code = "MethodNotAllowed"
	NotImplemented        Code = "NotImplemented"
	// NoSuchUpload and the five codes after it are the multipart set. Without
	// them the client sees a bare InternalError where the real answer is
	// actionable ("that upload id is gone", "part 3 was never written"), and an
	// SDK retry loop cannot tell a retryable failure from a permanent one.
	NoSuchUpload     Code = "NoSuchUpload"
	InvalidPart      Code = "InvalidPart"
	InvalidPartOrder Code = "InvalidPartOrder"
	EntityTooSmall   Code = "EntityTooSmall"
	MalformedXML     Code = "MalformedXML"
	InvalidRequest   Code = "InvalidRequest"
)

// Error is the S3 XML error document.
type Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

var messages = map[Code]string{
	AccessDenied:          "Access Denied",
	NoSuchKey:             "The specified key does not exist.",
	NoSuchBucket:          "The specified bucket does not exist",
	InvalidBucketName:     "The specified bucket is not valid.",
	InternalError:         "We encountered an internal error. Please try again.",
	SignatureDoesNotMatch: "The request signature we calculated does not match the signature you provided.",
	InvalidAccessKeyId:    "The AWS Access Key Id you provided does not exist in our records.",
	MethodNotAllowed:      "The specified method is not allowed against this resource.",
	NotImplemented:        "The requested operation is not implemented.",
	NoSuchUpload:          "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
	InvalidPart:           "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
	InvalidPartOrder:      "The list of parts was not in ascending order. Parts must be ordered by part number.",
	EntityTooSmall:        "Your proposed upload is smaller than the minimum allowed object size.",
	MalformedXML:          "The XML you provided was not well-formed or did not validate against our published schema.",
	InvalidRequest:        "The request is not valid.",
}

var status = map[Code]int{
	AccessDenied:          http.StatusForbidden,
	NoSuchKey:             http.StatusNotFound,
	NoSuchBucket:          http.StatusNotFound,
	InvalidBucketName:     http.StatusBadRequest,
	InternalError:         http.StatusInternalServerError,
	SignatureDoesNotMatch: http.StatusForbidden,
	InvalidAccessKeyId:    http.StatusForbidden,
	MethodNotAllowed:      http.StatusMethodNotAllowed,
	NotImplemented:        http.StatusNotImplemented,
	NoSuchUpload:          http.StatusNotFound,
	InvalidPart:           http.StatusBadRequest,
	InvalidPartOrder:      http.StatusBadRequest,
	EntityTooSmall:        http.StatusBadRequest,
	MalformedXML:          http.StatusBadRequest,
	InvalidRequest:        http.StatusBadRequest,
}

// WriteError writes an S3 XML error response.
func WriteError(w http.ResponseWriter, r *http.Request, code Code, message string) {
	if message == "" {
		message = messages[code]
	}
	st := status[code]
	if st == 0 {
		st = http.StatusInternalServerError
	}
	reqID := RequestID(r)
	body, err := xml.Marshal(Error{
		Code:      string(code),
		Message:   message,
		Resource:  r.URL.Path,
		RequestID: reqID,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", reqID)
	w.WriteHeader(st)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

// RequestID returns an existing x-amz-request-id or a fresh hex id.
func RequestID(r *http.Request) string {
	if r != nil {
		if id := r.Header.Get("x-amz-request-id"); id != "" {
			return id
		}
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
