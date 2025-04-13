package logout

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gorilla/sessions"
)

/*func ActivityMiddleware(store *sessions.CookieStore) func(http.Handler) http.Handler {
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
}*/

func updateLastActivity(w http.ResponseWriter,
	r *http.Request, store *sessions.CookieStore) bool {
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get session")
		return false
	}

	lastActivity, ok := session.Values["lastActivity"].(structs.LastActivity)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get value 'lastActivity' from session")
		return false
	}

	tokenExp := lastActivity.GetTokenExp()
	if time.Now().After(tokenExp) {
		activityExp := lastActivity.GetActivityExp()
		if time.Since(activityExp) > 3*time.Hour {
			delete(session.Values, "lastActivity")
			session.Save(r, w)
			http.Redirect()
		}
	}

}
