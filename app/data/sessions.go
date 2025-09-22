package data

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var loginStore *sessions.CookieStore
var captchaStore *sessions.CookieStore

func InitStore() *sessions.CookieStore {
	loginStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

	threeMinutes := 180
	loginStore.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   threeMinutes,
		Secure:   false,
	}

	captchaStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	captchaStore.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60, // One Month
		Secure:   false,
	}

	return loginStore
}

func InitSessionVarsMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := loginStore.Get(r, "auth")
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func SessionEnd(w http.ResponseWriter, r *http.Request) error {
	session, err := loginStore.Get(r, "auth")
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

func SessionDataSet(w http.ResponseWriter, r *http.Request, key string, consts any) error {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(consts)
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

func SessionUserDataGet(r *http.Request, key string) (structs.User, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return structs.User{}, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", key)))
	}

	var userData structs.User
	err = json.Unmarshal([]byte(byteData), &userData)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return userData, nil
}

func SessionIntDataGet(r *http.Request, key string) (int64, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return 0, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return 0, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", key)))
	}

	var intData int64
	err = json.Unmarshal([]byte(byteData), &intData)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return intData, nil
}

func SessionStringDataGet(r *http.Request, key string) (string, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return "", errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return "", errors.WithStack(errors.New(fmt.Sprintf("%s not exist", key)))
	}

	var stringData string
	err = json.Unmarshal([]byte(byteData), &stringData)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return stringData, nil
}

func SessionCaptchaDataSet(w http.ResponseWriter, r *http.Request, key string, consts any) error {
	session, err := captchaStore.Get(r, "captcha")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(consts)
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

func SessionCaptchaIntDataGet(r *http.Request, key string) (int64, error) {
	session, err := captchaStore.Get(r, "captcha")
	if err != nil {
		return 0, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return 0, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", key)))
	}

	var intData int64
	err = json.Unmarshal([]byte(byteData), &intData)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return intData, nil
}

func SessionTimeDataGet(r *http.Request, key string) (time.Time, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return time.Time{}, errors.WithStack(err)
	}

	byteData, ok := session.Values[key].([]byte)
	if !ok {
		return time.Time{}, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", key)))
	}

	var timeData time.Time
	err = json.Unmarshal([]byte(byteData), &timeData)
	if err != nil {
		return time.Time{}, errors.WithStack(err)
	}

	return timeData, nil
}
