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
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuId"
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
		"client_Id":     {os.Getenv("clientId")},
		"redirect_uri":  {consts.YandexCallbackFullURL},
		"scope":         {"login:email"},
	}
	authURLWithParams := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authURLWithParams, http.StatusFound)
}

func YandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	yauthCode := r.URL.Query().Get("code")
	if yauthCode == "" {
		err := errors.New("yauthCode not exist")
		tracedErr := errors.WithStack(err)
		errs.LogAndRedirectIfErrNotNill(w, r, tracedErr, consts.SignUpURL)
		return
	}

	yandexAccessToken, err := getAccessToken(yauthCode)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	yandexUser, err := getYandexUserInfo(yandexAccessToken)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tx, err := data.DB.Begin()
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	temporaryUserId := uuId.New().String()
	permanentUserId := uuId.New().String()
	temporaryUserIdCancelled := false

	pepermanentId, err := data.GetYauthUserFromDB(yandexUser.Login)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err = data.SetYauthUserInDBTx(tx, yandexUser.Login, yandexUser.Email, temporaryUserId, permanentUserId, temporaryUserIdCancelled); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		} else {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if pepermanentId != "" {
		permanentUserId = pepermanentId
	}
	data.SetTemporaryUserIdInCookie(w, temporaryUserId)

	if err = data.SetTemporaryUserIdInDbTx(tx, yandexUser.Login, temporaryUserId, temporaryUserIdCancelled); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	uniqueUserAgents, err := data.GetUniqueUserAgents(permanentUserId)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
	} else {
		isNewDevice := true
		for _, userAgent := range uniqueUserAgents {
			if userAgent == r.UserAgent() {
				isNewDevice = false
				break
			}
		}

		if isNewDevice {
			if err := tools.SendNewDeviceLoginEmail(yandexUser.Login, yandexUser.Email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			}
		}
	}

	refreshTokenCancelled := false
	if err = data.SetRefreshTokenTx(tx, permanentUserId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func getAccessToken(yauthCode string) (string, error) {
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {yauthCode},
		"client_Id":     {os.Getenv("clientId")},
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
	if err = json.Unmarshal(body, &result); err != nil {
		return "", errors.WithStack(err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		err := errors.New("access_token: not exist")
		return "", errors.WithStack(err)
	}

	return accessToken, nil
}

func getYandexUserInfo(accessToken string) (structs.User, error) {
	userInfoURLWithParams := userInfoURL + "?format=json&with_openId_Identity=1&with_email=1"

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
	if err = json.Unmarshal(body, &user); err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return user, nil
}
