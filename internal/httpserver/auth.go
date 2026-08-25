package httpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		got := bearer(r.Header.Get("Authorization"))
		if !tokenMatch(got, s.token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="s3vault"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(h string) string {
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func tokenMatch(got, want string) bool {
	gs := sha256.Sum256([]byte(got))
	ws := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gs[:], ws[:]) == 1
}
