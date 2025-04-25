package yauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/consts"
)

type YandexUser struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Email string `json:"default_email"`
}

func Router() {
	http.HandleFunc(consts.YandexAuthURL, yandexAuthHandler)         // Маршрут для начала авторизации через Яндекс
	http.HandleFunc(consts.YandexCallbackURL, yandexCallbackHandler) // Маршрут для обработки callback от Яндекса
}

// Обработчик для начала авторизации через Яндекс
func yandexAuthHandler(w http.ResponseWriter, r *http.Request) {
	authParams := url.Values{}
	authParams.Add(consts.ResponseTypeStr, consts.CodeStr)
	authParams.Add(consts.ClientIDStr, consts.ClientIDCodeStr)
	authParams.Add(consts.RedirectUrlStr, consts.RedirectURL) // URL, куда Яндекс перенаправит пользователя после авторизации

	// Формируем полный URL для авторизации
	authURLWithParamsUrl := consts.AuthURL + "?" + authParams.Encode() // Добавляем параметры к базовому URL авторизации

	// Перенаправляем пользователя на страницу авторизации Яндекса
	http.Redirect(w, r, authURLWithParamsUrl, http.StatusFound) // HTTP-статус 302 (перенаправление)
}

func yandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем параметр "code" из URL (он передается Яндексом после успешной авторизации)
	code := r.URL.Query().Get(consts.CodeStr)
	if code == consts.EmptyValueStr {
		http.Error(w, consts.AuthCodeNotFoundErr, http.StatusBadRequest)
		return
	}

	// Получаем access_token, используя код авторизации
	token, err := getAccessToken(code)
	if err != nil {
		http.Error(w, consts.YandexTokenGetFailedErr,
			http.StatusInternalServerError)
		log.Println(consts.YandexTokenGetFailedErr, err)
		return
	}

	// Получаем информацию о пользователе с помощью access_token
	user, err := getUserInfo(token)
	if err != nil {
		http.Error(w, consts.UserInfoGetFailedErr, http.StatusInternalServerError)
		log.Println(consts.UserInfoGetFailedErr, err)
		return
	}

	fmt.Fprintf(w, "User Info: %+v", user)
}

func getAccessToken(code string) (string, error) {
	tokenParams := url.Values{}
	tokenParams.Add(consts.GrandTypeStr, consts.AuthCodeStr)
	tokenParams.Add(consts.CodeStr, code)
	tokenParams.Add(consts.ClientIDStr, consts.ClientIDCodeStr)
	tokenParams.Add(consts.ClientSecret, consts.ClientSecretCodeStr)
	tokenParams.Add(consts.RedirectUrlStr, consts.RedirectURL)

	// Отправляем POST-запрос для получения токена
	resp, err := http.PostForm(consts.TokenURL, tokenParams) // Отправляем данные через форму
	if err != nil {
		return consts.EmptyValueStr, err
	}
	defer resp.Body.Close()

	// Читаем тело ответа
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return consts.EmptyValueStr, err
	}

	// Парсим JSON-ответ
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return consts.EmptyValueStr, err
	}

	// Извлекаем access_token из ответа
	accessToken, ok := result[consts.TokenStr].(string)
	if !ok {
		return consts.EmptyValueStr, fmt.Errorf(consts.TokenGetFailedErr)
	}

	return accessToken, nil
}

func getUserInfo(accessToken string) (*YandexUser, error) {
	// Создаем GET-запрос для получения данных пользователя
	req, err := http.NewRequest("GET", consts.UserInfoURL, nil)
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
