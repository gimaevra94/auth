package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

type User struct {
	ID       string `sql:"id" json:"id"`
	Login    string `sql:"login" json:"login"`
	Email    string `sql:"email" json:"email"`
	Password string `sql:"password" json:"password"`
}

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
		return nil, errors.WithStack(errors.New("token: " + tmpls.InvalidErr))
	}

	return token, nil
}

func IsValidInput(r *http.Request, IsLogin bool) (tmpls.User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	validatedLoginInput := tmpls.User{
		ID:       id,
		Login:    login,
		Email:    email,
		Password: password,
	}

	if login == "" {
		return tmpls.User{}, errors.WithStack(errors.New("login: " + tmpls.NotExistErr))
	}
	if !loginRegex.MatchString(login) {
		return tmpls.User{}, errors.WithStack(errors.New("login: " + tmpls.InvalidErr))
	}

	if !IsLogin {
		if email == "" {
			return tmpls.User{}, errors.WithStack(errors.New("email: " + tmpls.NotExistErr))
		}
		if !emailRegex.MatchString(email) {
			return tmpls.User{}, errors.WithStack(errors.New("email: " + tmpls.InvalidErr))
		}
	}

	if password == "" {
		return tmpls.User{}, errors.WithStack(errors.New("password: " + tmpls.NotExistErr))
	}
	if !passwordRegex.MatchString(password) {
		return tmpls.User{}, errors.WithStack(errors.New("password: " + tmpls.InvalidErr))
	}

	return validatedLoginInput, nil
}
