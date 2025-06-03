package auth

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/dataspace"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

const (
	clientID     = "0c0c69265b9549b7ae1b994a2aecbcfb"
	clientSecret = "a72af8c056c647c99d6b0ab470569b0b"
	authURL      = "https://oauth.yandex.ru/authorize "
	tokenURL     = "https://oauth.yandex.ru/token "
	userInfoURL  = "https://login.yandex.ru/info "
)

func YandexAuthHandler(w http.ResponseWriter, r *http.Request) {
	authParams := url.Values{
		"responseType": {"YaCode"},
		"clientId":     {clientID},
		"redirectUri":  {dataspace.HomeURL},
	}

	authURLWithParamsUrl := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authURLWithParamsUrl, http.StatusFound)
}

func YandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	yaCode := r.URL.Query().Get("YaCode")

	if yaCode == "" {
		newErr := errors.New(dataspace.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "YaCode")
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
		return
	}

	token, err := getAccessToken(yaCode)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
		return
	}

	user, err := getUserInfo(token)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
		return
	}

	err = dataspace.UserCheck(w, r, user, false)
	if err != nil {
		if err == sql.ErrNoRows {
			err = dataspace.UserAdd(w, r, user)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
				return
			}
		}
	}

	err = tools.TokenCreate(w, r, "true", user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
		return
	}

	cookie, err := r.Cookie("auth")
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
		return
	}

	w.Header().Set("auth", cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, dataspace.HomeURL, http.StatusFound)
}

func getAccessToken(yaCode string) (string, error) {
	tokenParams := url.Values{
		"grandType":    {"authorixation_code"},
		"yaCode":       {yaCode},
		"clientId":     {clientID},
		"clientSecret": {clientSecret},
		"redirectUrl":  {dataspace.HomeURL},
	}

	resp, err := http.PostForm(tokenURL, tokenParams)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		newErr := errors.New(dataspace.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "'access_token'")
		log.Printf("%+v", wrappedErr)
		return "", wrappedErr
	}

	return accessToken, nil
}

func getUserInfo(accessToken string) (dataspace.User, error) {
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	req.Header.Set("Authorization", "OAuth "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	var user dataspace.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, err
	}

	return user, nil
}
