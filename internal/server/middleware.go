package server

import (
	"bytes"
	"encoding/hex"
	"github.com/interfere/go-papyrus/v2/internal/papyrus"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"strings"
)

// NoStoreCacheControlMiddleware middleware to add `no-store` cache control to http writer
func NoStoreCacheControlMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
		})
	}
}

func PapyrusAuthMiddleware(service *papyrus.AuthService, lg *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
			signature := r.Header.Get("X-Signature")
			if token == "" || signature == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			sig, err := hex.DecodeString(signature)
			if err != nil {
				lg.Error("Failed to parse x-signature", zap.Error(err))
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if r.Body != nil {
				bodyBytes, err := ioutil.ReadAll(r.Body)
				if err != nil {
					lg.Error("Failed to read the body", zap.Error(err))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if !service.VerifySignature(token, sig, bodyBytes) {
					w.WriteHeader(http.StatusForbidden)
					return
				}

				r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			next.ServeHTTP(w, r)
		})
	}
}
