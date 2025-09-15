package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

type User struct {
	UserID   string `sql:"id" json:"user-id"`
	Login    string `sql:"login" json:"login"`
	Email    string `sql:"email" json:"email"`
	Password string `sql:"password" json:"password"`
}

var (
	loginRegex    = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	passwordRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ\d!@#$%^&*\-\)]{4,30}$`)
)

func AccessTokenValidator(token string) (*AccessTokenClaims, error) {

	signedToken, err := jwt.ParseWithClaims(token, &AccessTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			err := errors.New("unexpected signing method")
			return nil, errors.WithStack(err)
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims, ok := signedToken.Claims.(*AccessTokenClaims)
	if !ok {
		err := errors.New("Claims deserialize error")
		return nil, errors.WithStack(err)
	}

	if !signedToken.Valid {
		err := errors.New("Access token invalid")
		return nil, errors.WithStack(err)
	}

	return claims, nil
}

func RefreshTokenValidator(token string) (*RefreshTokenClaims, error) {
	signedToken, err := jwt.ParseWithClaims(token, &RefreshTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			err := errors.New("unexpected signing method")
			return nil, errors.WithStack(err)
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims, ok := signedToken.Claims.(*RefreshTokenClaims)
	if !ok {
		err := errors.New("Claims deserialize error")
		return nil, errors.WithStack(err)
	}

	if !signedToken.Valid {
		err := errors.New("Refresh token invalid")
		return nil, errors.WithStack(err)
	}

	return claims, nil
}

func InputValidator(r *http.Request, IsSignIn bool, IsPasswordReset bool) (User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	validatedLoginInput := User{
		UserID:   id,
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
