package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/golang-jwt/jwt"
)

var (
	loginRegex    = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	passwordRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ\d!@#$%^&*]{3,30}$`)
)

func IsValidToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	tokenSecret := os.Getenv("JWT_SECRET")
	if tokenSecret == "" {
		return nil, nil
	}

	cookie, _ := r.Cookie("auth")
	tokenValue := cookie.Value
	token, err := jwt.Parse(tokenValue, func(t *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return nil, errs.WithStackingErrPrintRedir(w, r, "", err)
	}

	if !token.Valid {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.InvalidErr, "token")
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter, r *http.Request) (data.User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if login == "" {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.NotExistErr,
			"login")
	}
	if !loginRegex.MatchString(login) {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.InvalidErr, "login")
	}

	if email == "" {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.NotExistErr, "email")
	}
	if !emailRegex.MatchString(email) {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.InvalidErr, "email")
	}

	if password == "" {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.NotExistErr, "password")
	}
	if !passwordRegex.MatchString(password) {
		return nil, errs.WrappingErrPrintRedir(w, r, "", data.InvalidErr, "password")
	}

	validatedLoginInput := data.NewUser(
		id,
		login,
		email,
		password,
	)
	return validatedLoginInput, nil
}
