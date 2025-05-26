package tools

import (
	"log"
	"net/http"
	"regexp"

	"github.com/gimaevra94/auth/app"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

var (
	loginRegex    = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	passwordRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ\d!@#$%^&*]{3,30}$`)
)

const (
	getFailedErr = "failed to get"
	invalidErr   = "invalid"
)

func IsValidToken(r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie("cookie")
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	tokenValue := cookie.Value
	if tokenValue == "" {
		newErr := errors.New(getFailedErr)
		wrappedErr := errors.Wrap(newErr, "'tokenValue'")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	token, err := jwt.Parse(tokenValue, func(t *jwt.Token) (interface{},
		error) {
		return []byte("my-super-secret-key"), nil
	})

	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	if !token.Valid {
		newErr := errors.New(invalidErr)
		wrappedErr := errors.Wrap(newErr, "token")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter, r *http.Request) (app.User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if login == "" {
		newErr := errors.New(getFailedErr)
		wrappedErr := errors.Wrap(newErr, "login")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}
	if !loginRegex.MatchString(login) {
		newErr := errors.New(invalidErr)
		wrappedErr := errors.Wrap(newErr, "login")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	if email == "" {
		newErr := errors.New(getFailedErr)
		wrappedErr := errors.Wrap(newErr, "email")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}
	if !emailRegex.MatchString(email) {
		newErr := errors.New(invalidErr)
		wrappedErr := errors.Wrap(newErr, "email")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	if password == "" {
		newErr := errors.New(getFailedErr)
		wrappedErr := errors.Wrap(newErr, "password")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}
	if !passwordRegex.MatchString(password) {
		newErr := errors.New(invalidErr)
		wrappedErr := errors.Wrap(newErr, "password")
		log.Printf("%+v", wrappedErr)
		return nil, wrappedErr
	}

	validatedLoginInput := app.NewUser(
		id,
		login,
		email,
		password,
	)
	return validatedLoginInput, nil
}
