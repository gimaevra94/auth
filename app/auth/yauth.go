package auth

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
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

func YandexCallbackHandler(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		yaCode := r.URL.Query().Get("code")

		if yaCode == "" {
			log.Printf("%+v", errors.WithStack(errors.New("code: "+data.NotExistErr)))
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		token, err := getAccessToken(yaCode)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		user, err := getUserInfo(token)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		err = data.YauthUserCheck(w, r, user)
		if err != nil {
			if err == sql.ErrNoRows {
				err = data.YauthUserAdd(w, r, user)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
					return
				}
			}
		}

		err = tools.TokenCreate(w, r, "true", user)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		err = tools.SessionUserSet(w, r, store, user)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
		}

		http.Redirect(w, r, data.HomeURL, http.StatusFound)
	}
}

func getAccessToken(yaCode string) (string, error) {
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {yaCode},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {data.HomeURL},
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
		return "", errors.WithStack(errors.New("access_token: " + data.NotExistErr))
	}

	return accessToken, nil
}

func getUserInfo(accessToken string) (data.User, error) {
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return data.User{}, errors.WithStack(err)
	}

	req.Header.Set("Authorization", "OAuth "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return data.User{}, errors.WithStack(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return data.User{}, errors.WithStack(err)
	}

	var user data.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return data.User{}, errors.WithStack(err)
	}

	return user, nil
}
