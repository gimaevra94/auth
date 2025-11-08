package auth

import (
	"database/sql"
	"encoding/json"
	"io"
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
	authURL               = "https://oauth.yandex.ru/authorize"
	tokenURL              = "https://oauth.yandex.ru/token"
	userInfoURL           = "https://login.yandex.ru/info"
	YandexCallbackFullURL = "http://localhost:8080/ya_callback"
)

func YandexAuthHandler(w http.ResponseWriter, r *http.Request) {
	authParams := url.Values{
		"response_type": {"code"},
		"client_Id":     {os.Getenv("clientId")},
		"redirect_uri":  {YandexCallbackFullURL},
		"scope":         {"login:email"},
	}
	authUrlWithParams := authURL + "?" + authParams.Encode()
	http.Redirect(w, r, authUrlWithParams, http.StatusFound)
}

func YandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	yauthCode := r.URL.Query().Get("code")
	if yauthCode == "" {
		err := errors.New("yauthCode not exist")
		tracedErr := errors.WithStack(err)
		tools.LogAndRedirectIfErrNotNill(w, r, tracedErr, consts.SignUpURL)
		return
	}

	yandexAccessToken, err := getAccessToken(yauthCode)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	yandexUser, err := getYandexUserInfo(yandexAccessToken)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tx, err := data.Db.Begin()
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	temporaryId := uuid.New().String()
	permanentId := uuid.New().String()
	temporaryIdCancelled := false

	bdPermanentId, err := data.GetPermanentIdFromDb(yandexUser.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err = data.SetYauthUserInDbTx(tx, yandexUser.Login, yandexUser.Email, temporaryId, permanentId, temporaryIdCancelled); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		} else {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if bdPermanentId != "" {
		permanentId = bdPermanentId
	}
	data.SetTemporaryIdInCookies(w, temporaryId)

	if err = data.SetTemporaryIdInDbByEmailTx(tx, yandexUser.Login, temporaryId, temporaryIdCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GeneraterefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	uniqueUserAgents, err := data.GetUniqueUserAgentsFromDb(permanentId)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
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
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	refreshTokenCancelled := false
	if err = data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
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
		"redirect_uri":  {YandexCallbackFullURL},
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
