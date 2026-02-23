package service

import (
	"net/http"

	"github.com/nicjohnson145/pauth/internal/storage"
	"github.com/nicjohnson145/hlp"
)

func BasicAuthMiddleware(store SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get our basic auth creds
			user, pass, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
				http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
				return
			}

			// Lookup our info in the store
			info, err := store.ReadLoginInfo(r.Context(), nil, hlp.Ptr(user))
			if err != nil {
				http.Error(w, "error fetching user info", http.StatusInternalServerError)
				return
			}

			// Compare them
			if !PasswordsMatch(pass, info.StoredPassword) {
				http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
				return
			}

			// if we're good, then drop a session object on the request so we can compare roles later in the pass
			newCtx := SetSessionInContext(r.Context(), &storage.Session{
				ID:   "basic-auth-ephemeral",
				User: info.User,
			})

			// They're good, send it
			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}
