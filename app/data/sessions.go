package data

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var loginStore *sessions.CookieStore
var captchaStore *sessions.CookieStore

func InitStore() *sessions.CookieStore {
	sessionAuthKey := []byte(os.Getenv("LOGIN_STORE_SESSION_AUTH_KEY"))
	sessionEncryptionKey := []byte(os.Getenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY"))
	loginStore = sessions.NewCookieStore(sessionAuthKey, sessionEncryptionKey)
	loginStoreLifeTime := 30 * 60
	loginStore.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   loginStoreLifeTime,
		Secure:   false,
	}

	sessionSecret := []byte(os.Getenv("CAPTCHA_STORE_SESSION_SECRET_KEY"))
	captchaStore = sessions.NewCookieStore(sessionSecret)
	captchaStoreLifeTime := 30 * 24 * 60 * 60
	captchaStore.Options = &sessions.Options{
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   captchaStoreLifeTime,
		Secure:   false,
	}

	return nil
}

func SetCaptchaDataInSession(w http.ResponseWriter, r *http.Request, key string, consts any) error {
	captchaSession, err := captchaStore.Get(r, "captchaStore")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(consts)
	if err != nil {
		return errors.WithStack(err)
	}

	captchaSession.Values[key] = jsonData
	err = captchaSession.Save(r, w)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

var SetAuthDataInSession = func(w http.ResponseWriter, r *http.Request, consts any) error {
	loginSession, err := loginStore.Get(r, "loginStore")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonData, err := json.Marshal(consts)
	if err != nil {
		return errors.WithStack(err)
	}

	loginSession.Values["user"] = jsonData
	if err = loginSession.Save(r, w); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

var GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
	session, err := captchaStore.Get(r, "captchaStore")
	if err != nil {
		return 0, errors.WithStack(err)
	}

	byteData, ok := session.Values["captchaCounter"].([]byte)
	if !ok {
		err := errors.New("captchaCounter not exist")
		return 0, errors.WithStack(err)
	}

	var intData int64
	if err = json.Unmarshal([]byte(byteData), &intData); err != nil {
		return 0, errors.WithStack(err)
	}

	return intData, nil
}

var GetShowCaptchaFromSession = func(r *http.Request) (bool, error) {
	session, err := captchaStore.Get(r, "captchaStore")
	if err != nil {
		return false, errors.WithStack(err)
	}

	byteData, ok := session.Values["showCaptcha"].([]byte)
	if !ok {
		err := errors.New("showCaptcha not exist")
		return false, errors.WithStack(err)
	}

	var boolData bool
	if err = json.Unmarshal([]byte(byteData), &boolData); err != nil {
		return false, errors.WithStack(err)
	}

	return boolData, nil
}

var GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
	session, err := loginStore.Get(r, "loginStore")
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	byteData, ok := session.Values["user"].([]byte)
	if !ok {
		err := errors.New("user not exist")
		return structs.User{}, errors.WithStack(err)
	}

	var userData structs.User
	if err = json.Unmarshal([]byte(byteData), &userData); err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return userData, nil
}

var EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
	session, err := loginStore.Get(r, "loginStore")
	if err != nil {
		return errors.WithStack(err)
	}

	session.Options.MaxAge = -1
	if err = session.Save(r, w); err != nil {
		return errors.WithStack(err)
	}

	captchaSession, err := captchaStore.Get(r, "captchaStore")
	if err != nil {
		return errors.WithStack(err)
	}

	captchaSession.Options.MaxAge = -1
	if err = captchaSession.Save(r, w); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
