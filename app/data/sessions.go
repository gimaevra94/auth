// Package data предоставляет функции для работы с базой данных сессиями и cookie.
//
// Файл содержит функции для управления сессиями пользователей:
//   - InitStore: инициализирует хранилища сессий для аутентификации и капчи
//   - SetCaptchaDataInSession: сохраняет данные капчи в сессии
//   - SetAuthDataInSession: сохраняет данные аутентификации в сессии
//   - GetCaptchaCounterFromSession: получает счетчик попыток капчи из сессии
//   - GetShowCaptchaFromSession: получает флаг отображения капчи из сессии
//   - GetAuthDataFromSession: получает данные пользователя из сессии
//   - EndAuthAndCaptchaSessions: завершает все сессии пользователя
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

// InitStore инициализирует хранилища сессий для аутентификации и капчи.
//
// Создает два CookieStore:
//   - loginStore: для сессий аутентификации (время жизни 30 минут)
//   - captchaStore: для сессий капчи (время жизни 30 дней)
//
// Использует переменные окружения для ключей:
//   - LOGIN_STORE_SESSION_AUTH_KEY: ключ аутентификации для сессий входа
//   - LOGIN_STORE_SESSION_ENCRYPTION_KEY: ключ шифрования для сессий входа
//   - CAPTCHA_STORE_SESSION_SECRET_KEY: секретный ключ для сессий капчи
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

// SetCaptchaDataInSession сохраняет данные капчи в сессии.
//
// Сериализует переданные данные в JSON и сохраняет их в сессии капчи
// под указанным ключом. При ошибке возвращает обернутое исключение.
//
// Параметры:
//   - w: http.ResponseWriter для сохранения сессии
//   - r: *http.Request для получения сессии
//   - key: ключ для сохранения данных в сессии
//   - consts: данные для сохранения (любой тип, сериализуемый в JSON)
var SetCaptchaDataInSession = func(w http.ResponseWriter, r *http.Request, key string, consts any) error {
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

// SetAuthDataInSession сохраняет данные аутентификации пользователя в сессии.
//
// Сериализует данные пользователя в JSON и сохраняет их в сессии входа
// под ключом "user". При ошибке возвращает обернутое исключение.
//
// Параметры:
//   - w: http.ResponseWriter для сохранения сессии
//   - r: *http.Request для получения сессии
//   - consts: данные пользователя для сохранения (любой тип, сериализуемый в JSON)
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

// GetCaptchaCounterFromSession получает счетчик попыток капчи из сессии.
//
// Извлекает значение "captchaCounter" из сессии капчи, десериализует
// из JSON и возвращает как int64. При ошибке возвращает обернутое исключение.
//
// Параметры:
//   - r: *http.Request для получения сессии
//
// Возвращает:
//   - int64: значение счетчика попыток капчи
//   - error: ошибка, если счетчик отсутствует или произошла ошибка десериализации
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

// GetShowCaptchaFromSession получает флаг отображения капчи из сессии.
//
// Извлекает значение "showCaptcha" из сессии капчи, десериализует
// из JSON и возвращает как bool. При ошибке возвращает обернутое исключение.
//
// Параметры:
//   - r: *http.Request для получения сессии
//
// Возвращает:
//   - bool: флаг, указывающий нужно ли отображать капчу
//   - error: ошибка, если флаг отсутствует или произошла ошибка десериализации
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

// GetAuthDataFromSession получает данные пользователя из сессии аутентификации.
//
// Извлекает значение "user" из сессии входа, десериализует
// из JSON и возвращает как structs.User. При ошибке возвращает обернутое исключение.
//
// Параметры:
//   - r: *http.Request для получения сессии
//
// Возвращает:
//   - structs.User: данные пользователя из сессии
//   - error: ошибка, если данные отсутствуют или произошла ошибка десериализации
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

// EndAuthAndCaptchaSessions завершает все сессии пользователя.
//
// Принудительно завершает сессии аутентификации и капчи путем установки
// MaxAge = -1 и очистки всех значений. Используется для выхода пользователя.
//
// Параметры:
//   - w: http.ResponseWriter для сохранения изменений сессии
//   - r: *http.Request для получения сессий
//
// Возвращает:
//   - error: ошибка при завершении сессий
var EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
	session, err := loginStore.Get(r, "loginStore")
	if err != nil {
		return errors.WithStack(err)
	}

	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})
	if err = session.Save(r, w); err != nil {
		return errors.WithStack(err)
	}

	captchaSession, err := captchaStore.Get(r, "captchaStore")
	if err != nil {
		return errors.WithStack(err)
	}

	captchaSession.Options.MaxAge = -1
	captchaSession.Values = make(map[interface{}]interface{})
	if err = captchaSession.Save(r, w); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
