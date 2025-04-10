package logout

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

type lastActivity struct {
	TokenExp     time.Time
	LastActivity time.Time
}

func ActivityMiddleware(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, 
			r *http.Request) {
			session, err := store.Get(r, "auth-session")
			if err != nil || session.IsNew {
				http.Redirect(w, r, "logout.html", http.StatusSeeOther)
				return
			}

			lastActivity, ok := session.Values["last_activity"].(lastActivity)
			if !ok {
				http.Redirect(w, r, "logout.html", http.StatusSeeOther)
				return
			}

			lastActivity.LastActivity = time.Now()
			session.Values["last_activity"] = lastActivity
			session.Save(r, w)

			next.ServeHTTP(w, r)
		})
	}
}
