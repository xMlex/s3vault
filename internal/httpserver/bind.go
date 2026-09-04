package httpserver

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrTokenRequired is returned when listen is not loopback and neither bearer
// token nor S3 frontend credentials are configured.
var ErrTokenRequired = errors.New("unauthenticated server on a non-loopback address")

// ErrS3CredsRequired is returned when a dedicated S3 listen address is set
// without frontend S3 access/secret keys.
var ErrS3CredsRequired = errors.New("S3 API listen address without S3 credentials")

// ListenIsLoopback reports whether addr binds only to a loopback address.
func ListenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkBind(listen, token string, s3API bool) error {
	if ListenIsLoopback(listen) {
		return nil
	}
	if token != "" || s3API {
		return nil
	}
	return fmt.Errorf("%w: listen %q accepts remote clients, so set one of: "+
		"server.token (env S3VAULT_SERVER_TOKEN) for the HTTP API, "+
		"or both server.s3_access_key and server.s3_secret_key "+
		"(env S3VAULT_SERVER_S3_ACCESS_KEY / S3VAULT_SERVER_S3_SECRET_KEY) for the S3 API; "+
		"or bind to 127.0.0.1 instead", ErrTokenRequired, listen)
}

func checkS3Listen(s3Listen string, s3API bool) error {
	if s3Listen == "" || s3API {
		return nil
	}
	return fmt.Errorf("%w: server.s3_listen is %q but the S3 API is off, so set both "+
		"server.s3_access_key and server.s3_secret_key "+
		"(env S3VAULT_SERVER_S3_ACCESS_KEY / S3VAULT_SERVER_S3_SECRET_KEY), "+
		"or clear server.s3_listen", ErrS3CredsRequired, s3Listen)
}
