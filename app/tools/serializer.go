package tools

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func SessionUserGetUnmarshal(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, app.User, error) {

	session, err := store.Get(r, "auth")
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, nil, err
	}

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		newErr := errors.New(app.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "user")
		log.Printf("%+v", wrappedErr)
		return nil, nil, wrappedErr
	}

	var user app.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, nil, err
	}

	return session, user, nil
}

func SessionUserSetMarshal(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore, user app.User) error {

	session, err := store.Get(r, "auth")
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return err
	}
	jsonData, err := json.Marshal(user)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return err
	}

	session.Values["user"] = jsonData
	err = session.Save(r, w)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return err
	}
	return nil
}
