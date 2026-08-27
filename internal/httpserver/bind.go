package httpserver

import (
	"errors"
	"net"
	"strings"
)

// ErrTokenRequired is returned when listen is not loopback and neither bearer
// token nor S3 frontend credentials are configured.
var ErrTokenRequired = errors.New("server.token or server.s3 credentials are required when listen is not loopback")

// ErrS3CredsRequired is returned when S3 listen is non-loopback (or requested)
// without frontend S3 access/secret keys.
var ErrS3CredsRequired = errors.New("server.s3_access_key and server.s3_secret_key are required for S3 API on non-loopback listen")

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
	return ErrTokenRequired
}

func checkS3Listen(s3Listen string, s3API bool) error {
	if s3Listen == "" {
		return nil
	}
	if !s3API {
		return ErrS3CredsRequired
	}
	if !ListenIsLoopback(s3Listen) && !s3API {
		return ErrS3CredsRequired
	}
	return nil
}
