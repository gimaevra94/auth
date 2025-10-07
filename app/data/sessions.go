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
	authKey := []byte(os.Getenv("SESSION_AUTH_KEY"))
	encryptionKey := []byte(os.Getenv("SESSION_ENCRYPTION_KEY"))

	loginStore = sessions.NewCookieStore(authKey, encryptionKey)
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

func AuthSessionDataSet(w http.ResponseWriter, r *http.Request, consts any) error {
	session, err := loginStore.Get(r, "user")
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

func CaptchaSessionDataSet(w http.ResponseWriter, r *http.Request, consts any) error {
	session, err := captchaStore.Get(r, "captcha")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(consts)
	if err != nil {
		return errors.WithStack(err)
	}
	session.Values["captcha"] = jsonData

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

func SessionCaptchaCounterGet(r *http.Request) (int64, error) {
	session, err := captchaStore.Get(r, "captcha")
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

func SessionCaptchaShowGet(r *http.Request) (bool, error) {
	session, err := captchaStore.Get(r, "captcha")
	if err != nil {
		return false, errors.WithStack(err)
	}

	byteData, ok := session.Values["captchaShow"].([]byte)
	if !ok {
		return false, errors.WithStack(errors.New(fmt.Sprintf("%s not exist", "captchaShow")))
	}

	var boolData bool
	err = json.Unmarshal([]byte(byteData), &boolData)
	if err != nil {
		return false, errors.WithStack(err)
	}

	return boolData, nil
}
