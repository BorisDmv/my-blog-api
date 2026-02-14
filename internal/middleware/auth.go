package middleware

import (
	"net/http"
	"strings"
)

func Auth(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
			if authHeader == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			expected := token
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				authHeader = strings.TrimSpace(authHeader[7:])
			}

			if authHeader != expected {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
