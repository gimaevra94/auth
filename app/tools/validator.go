package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/gimaevra94/auth/app/data"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var (
	loginRegex    = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	passwordRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ\d!@#$%^&*\-\)]{4,30}$`)
)

func IsValidToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	httpCookie, _ := r.Cookie("token")
	tokenValue := httpCookie.Value
	token, err := jwt.Parse(tokenValue, func(t *jwt.Token) (interface{}, error) {
		tokenSecret := os.Getenv("JWT_SECRET")
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return nil, errors.WithStack(err)

	}

	if !token.Valid {
		return nil, errors.WithStack(errors.New("token: " + data.InvalidErr))
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore, IsLogin bool) (data.User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	validatedLoginInput := data.User{
		ID:       id,
		Login:    login,
		Email:    email,
		Password: password,
	}

	if login == "" {
		return data.User{}, errors.WithStack(errors.New("login: " + data.NotExistErr))
	}
	if !loginRegex.MatchString(login) {
		return data.User{}, errors.WithStack(errors.New("login: " + data.InvalidErr))
	}

	if !IsLogin {
		if email == "" {
			return data.User{}, errors.WithStack(errors.New("email: " + data.NotExistErr))
		}
		if !emailRegex.MatchString(email) {
			return data.User{}, errors.WithStack(errors.New("email: " + data.InvalidErr))
		}
	}

	if password == "" {
		return data.User{}, errors.WithStack(errors.New("password: " + data.NotExistErr))
	}
	if !passwordRegex.MatchString(password) {
		return data.User{}, errors.WithStack(errors.New("password: " + data.InvalidErr))
	}

	return validatedLoginInput, nil
}
