package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore) {
	remember := r.FormValue("remember")
	if remember == "" {
		newErr := errors.New(app.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "remember")
		log.Println("%+v", wrappedErr)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		return
	}

	if got, want := remember, "true"; got != want {
		remember = "true"
	} else {
		remember = "false"
	}

	validatedLoginInput, err := tools.IsValidInput(w, r)
	if err != nil {
		log.Println("%+v", err)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		return
	}

	err = app.UserCheck(w, r, validatedLoginInput, true)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("%+v", err)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Println("%+v", err)
			http.Redirect(w, r, app.BadSignInURL, http.StatusFound)
			return

		}

		log.Println("%+v", err)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
	}

	tokenExp := r.FormValue("remember")
	err = tools.TokenCreate(w, r, tokenExp, validatedLoginInput)
	if err != nil {
		log.Println("%+v", err)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
	}

	cookie, err := r.Cookie(app.CookieNameStr)
	if err != nil {
		http.Redirect(w, r, app.SignUpURL, http.StatusFound)
	}
	w.Header().Set(app.CookieNameStr, app.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))

	session, err := store.Get(r, app.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.SessionGetFailedErr, err)
	}

	lastActivity := time.Now().Add(app.TokenLifetime3HoursInt)
	session.Values[app.LastActivityStr] = lastActivity
	http.Redirect(w, r, app.HomeURL, http.StatusFound)
}
