package s3api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
)

func TestMapAuthError(t *testing.T) {
	t.Parallel()

	code, _ := mapAuthError(port.ErrAuthUnavailable)
	assert.Equal(t, s3err.ServiceUnavailable, code)

	code, _ = mapAuthError(port.ErrAuthInternal)
	assert.Equal(t, s3err.InternalError, code)

	code, _ = mapAuthError(port.ErrAccessDenied)
	assert.Equal(t, s3err.AccessDenied, code)
}
