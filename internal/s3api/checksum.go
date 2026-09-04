package s3api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
)

// setChecksumSHA256 sets AWS flexible-checksum response headers from a hex
// plaintext SHA-256. Empty or invalid digests are skipped (header omitted).
func setChecksumSHA256(w http.ResponseWriter, shaHex string) {
	if shaHex == "" {
		return
	}
	raw, err := hex.DecodeString(shaHex)
	if err != nil || len(raw) != sha256.Size {
		return
	}
	w.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(raw))
	w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
}
