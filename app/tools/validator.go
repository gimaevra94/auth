package tools

import (
	"net/http"
	"os"
	"regexp"

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

	InvalidErr = "invalid"
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
		return nil, errors.WithStack(errors.New("token: " + InvalidErr))
	}

	return token, nil
}

func IsValidInput(r *http.Request, IsSignIn bool, IsPasswordReset bool) (User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	validatedLoginInput := User{
		ID:       id,
		Login:    login,
		Email:    email,
		Password: password,
	}

	if login == "" {
		return User{}, errors.WithStack(errors.New("login not exist"))
	}
	if !loginRegex.MatchString(login) {
		return User{}, errors.WithStack(errors.New("login invalid"))
	}

	if !IsSignIn {
		if email == "" {
			return User{}, errors.WithStack(errors.New("email not exist"))
		}
		if !emailRegex.MatchString(email) {
			return User{}, errors.WithStack(errors.New("email invalid"))
		}
	}

	if !IsPasswordReset {
		if password == "" {
			return User{}, errors.WithStack(errors.New("password not exist"))
		}
		if !passwordRegex.MatchString(password) {
			return User{}, errors.WithStack(errors.New("password invalid"))
		}
	}

	return validatedLoginInput, nil
}
