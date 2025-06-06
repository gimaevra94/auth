package auth

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
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
		"redirectUri":  {data.HomeURL},
	}

	authURLWithParamsUrl := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authURLWithParamsUrl, http.StatusFound)
}

func YandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	yaCode := r.URL.Query().Get("YaCode")

	if yaCode == "" {
		errs.WrappingErrPrintRedir(w, r, data.RequestErrorURL, data.NotExistErr, "YaCode")
		return
	}

	token, err := getAccessToken(w, r, yaCode)
	if err != nil {
		errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
		return
	}

	user, err := getUserInfo(w, r, token)
	if err != nil {
		errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
		return
	}

	err = data.UserCheck(w, r, user, false)
	if err != nil {
		if err == sql.ErrNoRows {
			err = data.UserAdd(w, r, user)
			if err != nil {
				errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
				return
			}
		}
	}

	err = tools.TokenCreate(w, r, "true", user)
	if err != nil {
		errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
		return
	}

	cookie, err := r.Cookie("auth")
	if err != nil {
		errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
		return
	}

	w.Header().Set("auth", cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, data.HomeURL, http.StatusFound)
}

func getAccessToken(w http.ResponseWriter, r *http.Request, yaCode string) (string, error) {
	tokenParams := url.Values{
		"grandType":    {"authorixation_code"},
		"yaCode":       {yaCode},
		"clientId":     {clientID},
		"clientSecret": {clientSecret},
		"redirectUrl":  {data.HomeURL},
	}

	resp, err := http.PostForm(tokenURL, tokenParams)
	if err != nil {
		return "", errs.WithStackingErrPrintRedir(w, r, "", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", errs.WrappingErrPrintRedir(w, r, "", data.NotExistErr, "'access_token'")
	}

	return accessToken, nil
}

func getUserInfo(w http.ResponseWriter, r *http.Request, accessToken string) (data.User, error) {
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	req.Header.Set("Authorization", "OAuth "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errs.WithStackingErrPrintRedir(w, r, "", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	var user data.User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	return user, nil
}
