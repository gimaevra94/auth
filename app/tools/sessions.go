package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

func InitStore() *sessions.CookieStore {
	OneMonth := 2592000
	store.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   OneMonth,
		Secure:   false,
	}

	return store
}

func InitSessionVarsMW() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := store.Get(r, "auth")
			if err != nil {
				fmt.Printf("%+v", errors.WithStack(err))
				http.Redirect(w, r, data.Err500URL, http.StatusFound)
				return
			}

			if session.IsNew {
				err := SessionDataSet(w, r, "loginCounter", 3)
				if err != nil {
					fmt.Printf("%+v", errors.WithStack(err))
					http.Redirect(w, r, data.Err500URL, http.StatusFound)
				}

				err = SessionDataSet(w, r, "loginTimer", time.Time{})
				if err != nil {
					fmt.Printf("%+v", errors.WithStack(err))
					http.Redirect(w, r, data.Err500URL, http.StatusFound)
				}
			}
		})
	}
}

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

func SessionDataSet(w http.ResponseWriter, r *http.Request, key string, data any) error {

	session, err := store.Get(r, "auth")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.WithStack(err)
	}

	session.Values[key] = jsonData
	err = session.Save(r, w)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SessionUserDataGet(r *http.Request, key string) (data.User, error) {
	session, err := store.Get(r, "auth")
	if err != nil {
		return data.User{}, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return data.User{}, errors.WithStack(errors.New(fmt.Sprintf("%s: "+data.NotExistErr, key)))
	}

	var userData data.User
	err = json.Unmarshal([]byte(byteData), &userData)
	if err != nil {
		return data.User{}, errors.WithStack(err)
	}

	return userData, nil
}

func SessionIntDataGet(r *http.Request, key string) (int64, error) {
	session, err := store.Get(r, "auth")
	if err != nil {
		return 0, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return 0, errors.WithStack(errors.New(fmt.Sprintf("%s: "+data.NotExistErr, key)))
	}

	var intData int64
	err = json.Unmarshal([]byte(byteData), &intData)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return intData, nil
}

func SessionStringDataGet(r *http.Request, key string) (string, error) {
	session, err := store.Get(r, "auth")
	if err != nil {
		return "", errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return "", errors.WithStack(errors.New(fmt.Sprintf("%s: "+data.NotExistErr, key)))
	}

	var stringData string
	err = json.Unmarshal([]byte(byteData), &stringData)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return stringData, nil
}

func SessionTimeDataGet(r *http.Request, key string) (time.Time, error) {
	session, err := store.Get(r, "auth")
	if err != nil {
		return time.Time{}, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return time.Time{}, errors.WithStack(errors.New(fmt.Sprintf("%s: "+data.NotExistErr, key)))
	}

	var timeData time.Time
	err = json.Unmarshal([]byte(byteData), &timeData)
	if err != nil {
		return time.Time{}, errors.WithStack(err)
	}

	return timeData, nil
}
