 	package auth

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	authURL     = "https://oauth.yandex.ru/authorize"
	tokenURL    = "https://oauth.yandex.ru/token"
	userInfoURL = "https://login.yandex.ru/info"
)

func YandexAuthHandler(w http.ResponseWriter, r *http.Request) {
	authParams := url.Values{
		"response_type": {"code"},
		"client_id":     {os.Getenv("clientID")},
		"redirect_uri":  {consts.YandexCallbackFullURL},
		"scope":         {"login:email"},
	}

	authURLWithParams := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authURLWithParams, http.StatusFound)
}

func YandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	yauthCode := r.URL.Query().Get("code")

	if yauthCode == "" {
		log.Printf("%+v", errors.WithStack(errors.New("yauthCode not exist")))
		// прямой заход без кода — отправляем на регистрацию
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		return
	}

	yandexAccessToken, err := getAccessToken(yauthCode)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	yandexUser, err := getYandexUserInfo(yandexAccessToken)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	temporaryUserID := uuid.New().String()
	permanentUserID := uuid.New().String()
	temporaryCancelled := false

	tx, err := data.DB.Begin()
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()
	defer tx.Rollback()

	pepermanentID, err := data.YauthUserCheck(yandexUser.Login)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = data.YauthUserAddTx(tx, yandexUser.Login, yandexUser.Email, temporaryUserID, permanentUserID, temporaryCancelled)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	if pepermanentID != "" {
		permanentUserID = pepermanentID
	}

	// Всегда устанавливаем куки после определения permanentUserID
	data.TemporaryUserIDCookieSet(w, temporaryUserID)
	log.Printf("yauth: TemporaryUserID cookie set. temporaryUserID: %s", temporaryUserID)

	log.Printf("yauth: Adding TemporaryUserID to database. login: %s, temporaryUserID: %s", yandexUser.Login, temporaryUserID)
	err = data.TemporaryUserIDAddTx(tx, yandexUser.Login, temporaryUserID, false)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// 1. Получить все сохраненные User-Agent'ы для этого пользователя
	storedUserAgents, err := data.GetAllUserAgentsForUser(permanentUserID) // Нужно реализовать эту функцию
	if err != nil {
		log.Printf("SignInUserCheck: Error fetching stored UserAgents: %+v", err)
		// Продолжаем, не будем блокировать вход из-за этой ошибки, но можно логировать
		// или установить флаг для отправки алерта только если не было ошибки
	} else {
		// 2. Проверить, есть ли текущий User-Agent среди сохраненных
		isNewDevice := true
		for _, ua := range storedUserAgents {
			if ua == r.UserAgent() { // Сравниваем с текущим User-Agent запроса
				isNewDevice = false
				break
			}
		}

		// 3. Если это новое устройство, отправить алерт
		if isNewDevice {
			login, email, _, _, errGetUser := data.MWUserCheck(temporaryUserID) // Получить login/email для письма
			if errGetUser == nil {                                              // Если получилось получить данные пользователя
				// Отправляем письмо "Suspicious Login Alert" (хотя это может быть легитимный вход)
				// Возможно, стоит изменить текст письма или использовать отдельную функцию для "New Device Login"
				errAlert := tools.SendNewDeviceLoginEmail(login, email, r.UserAgent()) // Используем текущий UA как "подозрительное" устройство
				if errAlert != nil {
					log.Printf("SignInUserCheck: Error sending new device alert email: %+v", errAlert)
					// Не перенаправляем на ошибку 500 из-за сбоя отправки письма
				} else {
					log.Printf("SignInUserCheck: New device alert email sent for user %s (%s) from %s", login, email, r.UserAgent())
				}
			} else {
				log.Printf("SignInUserCheck: Could not fetch user details to send new device alert: %+v", errGetUser)
			}
		}
	}

	tokenCancelled := false
	err = data.RefreshTokenAddTx(tx, permanentUserID, refreshToken, r.UserAgent(), tokenCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Логируем заголовки перед редиректом
	log.Printf("yauth: Before redirect to HomeURL. Response Set-Cookie header: %v", w.Header().Get("Set-Cookie"))
	log.Printf("yauth: Before redirect to HomeURL. Request cookies: %+v", r.Cookies())
	// Помечаем вход через Яндекс кукой
	http.SetCookie(w, &http.Cookie{
		Name:     "yauth",
		Value:    "1",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIDExp,
	})

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func getAccessToken(yauthCode string) (string, error) {
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {yauthCode},
		"client_id":     {os.Getenv("clientID")},
		"client_secret": {os.Getenv("clientSecret")},
		"redirect_uri":  {consts.YandexCallbackFullURL},
	}

	resp, err := http.PostForm(tokenURL, tokenParams)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithStack(err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", errors.WithStack(err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", errors.WithStack(errors.New("access_token: not exist"))
	}

	return accessToken, nil
}

func getYandexUserInfo(accessToken string) (structs.User, error) {
	userInfoURLWithParams := userInfoURL + "?format=json&with_openid_identity=1&with_email=1"

	req, err := http.NewRequest("GET", userInfoURLWithParams, nil)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	req.Header.Set("Authorization", "OAuth "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	var user structs.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return user, nil
}
