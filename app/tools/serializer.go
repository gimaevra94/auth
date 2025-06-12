package tools

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gorilla/sessions"
)

func SessionUserSet(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore, user data.User) error {

	session, err := store.Get(r, "auth")
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	session.Values["user"] = jsonData
	err = session.Save(r, w)
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	return nil
}

func SessionUserGet(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, data.User, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, nil, errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		return nil, nil, errs.NewErrWrapPrintRedir(w, r, "", data.NotExistErr, "user")
	}

	var u struct {
		ID       string `json:"id"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err = json.Unmarshal([]byte(jsonData), &u)
	if err != nil {
		return nil, nil, errs.OrigErrWrapPrintRedir(w, r, "", err)

	}

	user := data.NewUser(u.ID, u.Login, u.Email, u.Password)

	return session, user, nil
}

func SetlastActivityKeyForSession(w http.ResponseWriter, r *http.Request,
	session *sessions.Session) error {
	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity
	err := session.Save(r, w)
	if err != nil {
		errs.OrigErrWrapPrintRedir(w, r, "", err)
	}
	return nil
}
