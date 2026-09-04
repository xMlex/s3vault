package s3api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetChecksumSHA256(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("payload"))
	hexSum := hex.EncodeToString(sum[:])
	want := base64.StdEncoding.EncodeToString(sum[:])

	cases := []struct {
		name    string
		shaHex  string
		wantHdr string
		wantTyp string
	}{
		{name: "valid", shaHex: hexSum, wantHdr: want, wantTyp: "FULL_OBJECT"},
		{name: "empty", shaHex: ""},
		{name: "invalid", shaHex: "deadbeef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			setChecksumSHA256(rec, tc.shaHex)
			assert.Equal(t, tc.wantHdr, rec.Header().Get("x-amz-checksum-sha256"))
			assert.Equal(t, tc.wantTyp, rec.Header().Get("x-amz-checksum-type"))
		})
	}
}
