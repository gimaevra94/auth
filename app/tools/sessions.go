package tools

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func SessionUserSet(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore, user data.User) error {

	session, err := store.Get(r, "auth")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		return errors.WithStack(err)
	}

	session.Values["user"] = jsonData
	err = session.Save(r, w)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func SessionUserGet(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, data.User, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, data.User{}, errors.WithStack(err)
	}

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		return nil, data.User{}, errors.WithStack(errors.New("user: " + data.NotExistErr))
	}

	var user data.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		return nil, data.User{}, errors.WithStack(err)
	}

	return session, user, nil
}

func SetlastActivityKeyForSession(w http.ResponseWriter, r *http.Request,
	session *sessions.Session) error {
	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity
	err := session.Save(r, w)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
