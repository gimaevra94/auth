package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

var (
	loginRegex    = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	passwordRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ\d!@#$%^&*\-\)]{4,30}$`)
)

func InputValIdate(r *http.Request, login, email, password string, IsSignIn bool) error {
	if login == "" || !loginRegex.MatchString(login) {
		return errors.WithStack(errors.New("login invalId"))
	}

	if password == "" || !passwordRegex.MatchString(password) {
		return errors.WithStack(errors.New("password invalId"))
	}

	if !IsSignIn {
		if email == "" || !emailRegex.MatchString(email) {
			return errors.WithStack(errors.New("email invalId"))
		}
	}

	return nil
}

func RefreshTokenValIdate(refreshToken string) error {
	signedToken, err := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.WithStack(errors.New("unexpected signing method"))
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if !signedToken.ValId {
		err := errors.New("Refresh token invalId")
		return errors.WithStack(err)
	}

	return nil
}

func CodeValIdate(r *http.Request, clientCode, serverCode string) error {
	if clientCode == "" {
		return errors.WithStack(errors.New("clientCode not exist"))
	}

	if clientCode != serverCode {
		return errors.WithStack(errors.New("codes not match"))
	}
	return nil
}

func EmailValIdate(email string) error {
	if email == "" || !emailRegex.MatchString(email) {
		return errors.WithStack(errors.New("email invalId"))
	}
	return nil
}

func PasswordValIdate(password string) error {
	if password == "" || !passwordRegex.MatchString(password) {
		return errors.WithStack(errors.New("password invalId"))
	}
	return nil
}
