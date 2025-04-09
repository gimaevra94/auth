package logout

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

type sessionData struct {
	TokenExp     time.Time
	LastActivity time.Time
}

func ActivityMiddleware(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := store.Get(r, "auth-session")
			if err != nil || session.IsNew {
				http.Redirect(w, r, "logout.html", http.StatusSeeOther)
				return
			}

			sessionData, ok := session.Values["session_data"].(sessionData)
			if !ok {
				http.Redirect(w, r, "logout.html", http.StatusSeeOther)
				return
			}

			sessionData.LastActivity = time.Now()
			session.Values["session_data"] = sessionData
			session.Save(r, w)

			next.ServeHTTP(w, r)
		})
	}
}
