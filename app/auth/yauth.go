package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app"
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
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {app.RedirectURL},
	}

	// Формируем полный URL для авторизации
	authURLWithParamsUrl := app.AuthURL + "?" + authParams.Encode() // Добавляем параметры к базовому URL авторизации

	// Перенаправляем пользователя на страницу авторизации Яндекса
	http.Redirect(w, r, authURLWithParamsUrl, http.StatusFound) // HTTP-статус 302 (перенаправление)
}

func yandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем параметр "code" из URL (он передается Яндексом после успешной авторизации)
	code := r.URL.Query().Get(app.CodeStr)
	if code == app.EmptyValueStr {
		http.Error(w, app.AuthCodeNotFoundErr, http.StatusBadRequest)
		return
	}

	// Получаем access_token, используя код авторизации
	token, err := getAccessToken(code)
	if err != nil {
		http.Error(w, app.YandexTokenGetFailedErr,
			http.StatusInternalServerError)
		log.Println(app.YandexTokenGetFailedErr, err)
		return
	}

	// Получаем информацию о пользователе с помощью access_token
	user, err := getUserInfo(token)
	if err != nil {
		http.Error(w, app.UserInfoGetFailedErr, http.StatusInternalServerError)
		log.Println(app.UserInfoGetFailedErr, err)
		return
	}

	fmt.Fprintf(w, "User Info: %+v", user)
}

func getAccessToken(code string) (string, error) {
	tokenParams := url.Values{}
	tokenParams.Add(app.GrandTypeStr, app.AuthCodeStr)
	tokenParams.Add(app.CodeStr, code)
	tokenParams.Add(app.ClientIDStr, app.ClientIDCodeStr)
	tokenParams.Add(app.ClientSecret, app.ClientSecretCodeStr)
	tokenParams.Add(app.RedirectUrlStr, app.RedirectURL)

	// Отправляем POST-запрос для получения токена
	resp, err := http.PostForm(app.TokenURL, tokenParams) // Отправляем данные через форму
	if err != nil {
		return app.EmptyValueStr, err
	}
	defer resp.Body.Close()

	// Читаем тело ответа
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return app.EmptyValueStr, err
	}

	// Парсим JSON-ответ
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return app.EmptyValueStr, err
	}

	// Извлекаем access_token из ответа
	accessToken, ok := result[app.TokenStr].(string)
	if !ok {
		return app.EmptyValueStr, fmt.Errorf(app.TokenGetFailedErr)
	}

	return accessToken, nil
}

func getUserInfo(accessToken string) (*YandexUser, error) {
	// Создаем GET-запрос для получения данных пользователя
	req, err := http.NewRequest("GET", app.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	// Добавляем заголовок Authorization с access_token
	req.Header.Set("Authorization", "OAuth "+accessToken) // Устанавливаем заголовок для авторизации

	// Отправляем запрос
	client := &http.Client{}    // Создаем HTTP-клиент
	resp, err := client.Do(req) // Отправляем запрос
	if err != nil {             // Если произошла ошибка при отправке запроса
		return nil, err // Возвращаем nil и ошибку
	}
	defer resp.Body.Close() // Закрываем тело ответа после завершения работы

	// Читаем тело ответа
	body, err := ioutil.ReadAll(resp.Body) // Читаем все данные из тела ответа
	if err != nil {                        // Если произошла ошибка при чтении
		return nil, err // Возвращаем nil и ошибку
	}

	// Парсим JSON-ответ
	var user YandexUser               // Создаем структуру для хранения данных пользователя
	err = json.Unmarshal(body, &user) // Преобразуем JSON в структуру
	if err != nil {                   // Если произошла ошибка при парсинге
		return nil, err // Возвращаем nil и ошибку
	}

	return &user, nil // Возвращаем указатель на структуру пользователя и nil как ошибку
}
