package auth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

const (
	clientID     = "0c0c69265b9549b7ae1b994a2aecbcfb"
	clientSecret = "a72af8c056c647c99d6b0ab470569b0b"
	authURL      = "https://oauth.yandex.ru/authorize "
	tokenURL     = "https://oauth.yandex.ru/token "
	userInfoURL  = "https://login.yandex.ru/info "
)

// Обработчик для начала авторизации через Яндекс
func YandexAuthHandler(w http.ResponseWriter, r *http.Request) {
	authParams := url.Values{
		"responseType": {"YaCode"},
		"clientId":     {clientID},
		"redirectUri":  {app.HomeURL},
	}
	authURLWithParamsUrl := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authURLWithParamsUrl, http.StatusFound)
}

func YandexCallbackHandler(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		yaCode := r.URL.Query().Get("YaCode")
		if yaCode == "" {
			newErr := errors.New(app.NotExistErr)
			wrappedErr := errors.Wrap(newErr, "YaCode")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		token, err := getAccessToken(yaCode)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		user, err := getUserInfo(token)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		session, err := store.Get(r, "auth")
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		session, user, err := tools.SessionUserGetUnmarshal(r, store)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return err
		}



	}
}

func getAccessToken(yaCode string) (string, error) {
	tokenParams := url.Values{
		"grandType":    {"authorixation_code"},
		"yaCode":       {yaCode},
		"clientId":     {clientID},
		"clientSecret": {clientSecret},
		"redirectUrl":  {app.HomeURL},
	}

	// Отправляем POST-запрос для получения токена
	resp, err := http.PostForm(tokenURL, tokenParams) // Отправляем данные через форму
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}
	defer resp.Body.Close()

	// Читаем тело ответа
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}

	// Парсим JSON-ответ
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}

	// Извлекаем access_token из ответа
	accessToken, ok := result["access_token"].(string)
	if !ok {
		newErr := errors.New(app.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "'access_token'")
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}

	return accessToken, nil
}

func getUserInfo(accessToken string) (*app.User, error) {
	// Создаем GET-запрос для получения данных пользователя
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	// Добавляем заголовок Authorization с access_token
	req.Header.Set("Authorization", "OAuth "+accessToken) // Устанавливаем заголовок для авторизации

	// Отправляем запрос
	client := &http.Client{}    // Создаем HTTP-клиент
	resp, err := client.Do(req) // Отправляем запрос
	if err != nil {             // Если произошла ошибка при отправке запроса
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr // Возвращаем nil и ошибку
	}
	defer resp.Body.Close() // Закрываем тело ответа после завершения работы

	// Читаем тело ответа
	body, err := io.ReadAll(resp.Body) // Читаем все данные из тела ответа
	if err != nil {                    // Если произошла ошибка при чтении
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr // Возвращаем nil и ошибку
	}

	// Парсим JSON-ответ
	var user app.User                 // Создаем структуру для хранения данных пользователя
	err = json.Unmarshal(body, &user) // Преобразуем JSON в структуру
	if err != nil {                   // Если произошла ошибка при парсинге
		return nil, err // Возвращаем nil и ошибку
	}

	return &user, nil // Возвращаем указатель на структуру пользователя и nil как ошибку
}

func yaLogIn(w http.ResponseWriter, r *http.Request, user *app.User,
	store *sessions.CookieStore) error {
	rememberMe := "true"

	cookie, err := r.Cookie("auth")
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		return wrappedErr
	}

					err = app.UserCheck(w, r, *validatedLoginInput, true)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("%+v", err)
				http.Redirect(w, r, app.UserNotExistURL, http.StatusFound)
				return
			}

	err = app.UserAdd(w, r, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		return err
	}

	err = tools.TokenCreate(w, r, rememberMe, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		return err
	}

	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity
	err = session.Save(r, w)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
	}

	w.Header().Set("auth", cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, app.HomeURL, http.StatusFound)

	return nil
}
