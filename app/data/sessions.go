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

	sessionSecret := []byte(os.Getenv("SESSION_SECRET"))
	captchaStore = sessions.NewCookieStore(sessionSecret)
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

func LoginSessionGet(r *http.Request) (*sessions.Session, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return session, nil
}

func SetCaptchaDataInSession(w http.ResponseWriter, r *http.Request, key string, consts any) error {
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

func SetAuthSessionData(w http.ResponseWriter, r *http.Request, consts any) error {
	session, err := loginStore.Get(r, "auth")
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

func GetCaptchaCounterFromSession(r *http.Request) (int64, error) {
	session, err := captchaStore.Get(r, "captcha")
	if err != nil {
		return 0, errors.WithStack(err)
	}

	byteData, ok := session.Values["captchaCounter"].([]byte)
	if !ok {
		err := errors.New("captchaCounter not exist")
		return 0, errors.WithStack(err)
	}

	var intData int64
	err = json.Unmarshal([]byte(byteData), &intData)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return intData, nil
}

func GetShowCaptchaFromSession(r *http.Request) (bool, error) {
	session, err := captchaStore.Get(r, "captcha")
	if err != nil {
		return false, errors.WithStack(err)
	}

	byteData, ok := session.Values["ShowCaptcha"].([]byte)
	if !ok {
		err := errors.New("ShowCaptcha not exist")
		return false, errors.WithStack(err)
	}

	var boolData bool
	err = json.Unmarshal([]byte(byteData), &boolData)
	if err != nil {
		return false, errors.WithStack(err)
	}

	return boolData, nil
}

func GetUserFromSession(r *http.Request) (structs.User, error) {
	session, err := loginStore.Get(r, "auth")
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	byteData, ok := session.Values["user"].([]byte)
	if !ok {
		err := errors.New("user not exist")
		return structs.User{}, errors.WithStack(err)
	}

	var userData structs.User
	err = json.Unmarshal([]byte(byteData), &userData)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return userData, nil
}

func EndAuthSession(w http.ResponseWriter, r *http.Request) error {
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

func CaptchaSessionEnd(w http.ResponseWriter, r *http.Request) error {
	session, err := captchaStore.Get(r, "captcha")
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
