package httpserver

import (
	"errors"
	"net"
	"strings"
)

// ErrTokenRequired is returned when listen is not loopback and the bearer token is empty.
var ErrTokenRequired = errors.New("server.token is required when listen is not loopback")

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

func checkBind(listen, token string) error {
	if token == "" && !ListenIsLoopback(listen) {
		return ErrTokenRequired
	}
	return nil
}
