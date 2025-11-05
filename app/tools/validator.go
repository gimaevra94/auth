package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/gimaevra94/auth/app/structs"

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
		err := errors.New("login invalid")
		return errors.WithStack(err)
	}

	if password == "" || !passwordRegex.MatchString(password) {
		err := errors.New("password invalid")
		return errors.WithStack(err)
	}

	if !IsSignIn {
		if email == "" || !emailRegex.MatchString(email) {
			err := errors.New("email invalid")
			return errors.WithStack(err)
		}
	}

	return nil
}

func RefreshTokenValIdate(refreshToken string) error {
	signedToken, err := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			err := errors.New("unexpected signing method")
			return nil, errors.WithStack(err)
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if !signedToken.Valid {
		err := errors.New("Refresh token invalid")
		return errors.WithStack(err)
	}

	return nil
}

func CodeValIdate(r *http.Request, clientCode, serverCode string) error {
	if clientCode == "" {
		err := errors.New("clientCode not exist")
		return errors.WithStack(err)
	}

	if clientCode != serverCode {
		err := errors.New("codes not match")
		return errors.WithStack(err)
	}
	return nil
}

func EmailValIdate(email string) error {
	if email == "" || !emailRegex.MatchString(email) {
		err := errors.New("email invalid")
		return errors.WithStack(err)
	}
	return nil
}

func PasswordValIdate(password string) error {
	if password == "" || !passwordRegex.MatchString(password) {
		err := errors.New("password invalid")
		return errors.WithStack(err)
	}
	return nil
}

func ValIdateResetToken(signedToken string) (*structs.ResetClaims, error) {
	claims := &structs.ResetClaims{}

	tok, err := jwt.ParseWithClaims(signedToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !tok.Valid {
		return nil, errors.New("token invalId")
	}

	return claims, nil
}
