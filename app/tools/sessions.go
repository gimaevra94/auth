package tools

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

func InitStore() *sessions.CookieStore {
	store.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   86400,
		Secure:   false,
	}

	return store
}

/*func GetSession(r *http.Request) (*sessions.Session, error) {
	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return session, nil
}*/

func SessionEnd(w http.ResponseWriter, r *http.Request) error {
	session, err := store.Get(r, "auth")
	if err != nil {
		return errors.WithStack(err)
	}

	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SessionDataSet(w http.ResponseWriter, r *http.Request, data any) error {

	session, err := store.Get(r, "auth")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(data)
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

func SessionUserGet(r *http.Request) (*sessions.Session, data.User, error) {

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

func SessionCounterGet(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, int, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, 0, errors.WithStack(err)
	}

	jsonData, ok := session.Values["counter"].([]byte)
	if !ok {
		return nil, 0, errors.WithStack(errors.New("counter: " + data.NotExistErr))
	}

	var counter int
	err = json.Unmarshal([]byte(jsonData), &counter)
	if err != nil {
		return nil, 0, errors.WithStack(err)
	}

	return session, counter, nil
}

func SessionMsCodeGet(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, string, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, "", errors.WithStack(err)
	}

	jsonData, ok := session.Values["msCode"].([]byte)
	if !ok {
		return nil, "", errors.WithStack(errors.New("user: " + data.NotExistErr))
	}

	var msCode string
	err = json.Unmarshal([]byte(jsonData), &msCode)
	if err != nil {
		return nil, "", errors.WithStack(err)
	}

	return session, msCode, nil
}

func SessionlastActivityGet(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, time.Time, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		return nil, time.Time{}, errors.WithStack(err)
	}

	jsonData, ok := session.Values["msCode"].([]byte)
	if !ok {
		return nil, time.Time{}, errors.WithStack(errors.New("user: " + data.NotExistErr))
	}

	var lastActivity time.Time
	err = json.Unmarshal([]byte(jsonData), &lastActivity)
	if err != nil {
		return nil, time.Time{}, errors.WithStack(err)
	}

	return session, lastActivity, nil
}
