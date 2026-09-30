package httpserver

import (
	"errors"
	"fmt"
)

// ErrS3CredsRequired is returned when s3vault server starts without the S3
// frontend credentials. After the HTTP /files frontend was removed, the S3 API
// is the gateway's only data frontend; without it the server would serve
// nothing but health/readiness.
var ErrS3CredsRequired = errors.New("S3 API credentials required")

// requireS3API refuses a gateway without the SigV4 S3 frontend.
func requireS3API(s3API bool) error {
	if s3API {
		return nil
	}

	return fmt.Errorf("%w: set both server.s3_access_key and server.s3_secret_key "+
		"(env S3VAULT_SERVER_S3_ACCESS_KEY / S3VAULT_SERVER_S3_SECRET_KEY); "+
		"the gateway serves clients only over the S3 protocol", ErrS3CredsRequired)
}
