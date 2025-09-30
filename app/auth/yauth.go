package auth

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	clientID     = "0c0c69265b9549b7ae1b994a2aecbcfb"
	clientSecret = "a72af8c056c647c99d6b0ab470569b0b"
	authURL      = "https://oauth.yandex.ru/authorize"
	tokenURL     = "https://oauth.yandex.ru/token"
	userInfoURL  = "https://login.yandex.ru/info"
)

func YandexAuthHandler(w http.ResponseWriter, r *http.Request) {
	authParams := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {"/ya_callback"},
	}

	authURLWithParamsUrl := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authURLWithParamsUrl, http.StatusFound)
}

func YandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionGetUser(r)
	if err != nil {
		log.Printf("%v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	}

	yauthCode := r.URL.Query().Get("code")

	if yauthCode == "" {
		log.Printf("%+v", errors.WithStack(errors.New("yauthCode not exist")))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	yandexAccessToken, err := getAccessToken(yauthCode)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, false)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tools.RefreshTokenValidator(refreshToken)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	}

	yandexUser, err := getYandexUserInfo(yandexAccessToken)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.YauthUserCheck(yandexUser.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			err = data.YauthUserAdd(yandexUser.Login, yandexUser.Email)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		}
	}

	rememberMe := r.FormValue("rememberMe") != ""
	temporaryUserID := uuid.New().String()

	userPreferences := structs.UserPreferences{
		TemporaryUserID: temporaryUserID,
		RememberMe:      rememberMe,
	}

	err = data.TemporaryUserIDAdd(user.Login, temporaryUserID)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	jsonData, err := json.Marshal(userPreferences)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	data.UserPreferenceCookieSet(w, jsonData)

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func getAccessToken(yauthCode string) (string, error) {
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {yauthCode},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {consts.HomeURL},
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
	req, err := http.NewRequest("GET", userInfoURL, nil)
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
