package tools

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gorilla/sessions"
)

func SessionUserGetUnmarshal(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, data.User, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, nil, errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		return nil, nil, errs.WrappingErrPrintRedir(w, r, "", data.NotExistErr, "user")
	}

	var user data.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		return nil, nil, errs.WithStackingErrPrintRedir(w, r, "", err)

	}

	return session, user, nil
}

func SessionUserSetMarshal(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore, user data.User) error {

	session, err := store.Get(r, "auth")
	if err != nil {
		return errs.WithStackingErrPrintRedir(w, r, "", err)
	}
	jsonData, err := json.Marshal(user)
	if err != nil {
		return errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	session.Values["user"] = jsonData
	err = session.Save(r, w)
	if err != nil {
		return errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	return nil
}

func SetlastActivityKeyForSession(w http.ResponseWriter, r *http.Request,
	session *sessions.Session) error {
	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity
	err := session.Save(r, w)
	return errs.WithStackingErrPrintRedir(w, r, "", err)
}
