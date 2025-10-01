package data

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var loginStore *sessions.CookieStore
var captchaStore *sessions.CookieStore

func InitStore() *sessions.CookieStore {
	loginStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	thirtyMinutes := 30 * 60
	loginStore.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   thirtyMinutes,
		Secure:   false,
	}

	captchaStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	thirtyDays := 30 * 24 * 60 * 60
	captchaStore.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   thirtyDays,
		Secure:   false,
	}
	return nil
}

func AuthSessionEnd(w http.ResponseWriter, r *http.Request) error {
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

func SessionDataSet(w http.ResponseWriter, r *http.Request, storeName string, consts any) error {
	session, err := loginStore.Get(r, storeName)
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(consts)
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

func SessionUserGet(r *http.Request) (structs.User, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	byteData, ok := session.Values["user"].([]byte)
	if !ok {
		return structs.User{}, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", "user")))
	}

	var userData structs.User
	err = json.Unmarshal([]byte(byteData), &userData)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return userData, nil
}

func SessionCaptchaGet(r *http.Request, storeName string) (int64, error) {
	session, err := loginStore.Get(r, storeName)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	byteData, ok := session.Values["captchaCounter"].([]byte)
	if !ok {
		return 0, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", "captchaCounter")))
	}

	var intData int64
	err = json.Unmarshal([]byte(byteData), &intData)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return intData, nil
}
