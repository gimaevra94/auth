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

func RefreshTokenValidator(token string) (*structs.RefreshTokenClaims, error) {
	signedToken, err := jwt.ParseWithClaims(token, &structs.RefreshTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			err := errors.New("unexpected signing method")
			return nil, errors.WithStack(err)
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims, ok := signedToken.Claims.(*structs.RefreshTokenClaims)
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

func AccessTokenValidator(token string) (*structs.AccessTokenClaims, error) {

	signedToken, err := jwt.ParseWithClaims(token, &structs.AccessTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			err := errors.New("unexpected signing method")
			return nil, errors.WithStack(err)
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims, ok := signedToken.Claims.(*structs.AccessTokenClaims)
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

func InputValidator(r *http.Request, IsSignIn bool, IsPasswordReset bool) (structs.User, error) {

	id := ""
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	validatedLoginInput := structs.User{
		UserID:   id,
		Login:    login,
		Email:    email,
		Password: password,
	}

	if login == "" {
		return structs.User{}, errors.WithStack(errors.New("login not exist"))
	}
	if !loginRegex.MatchString(login) {
		return structs.User{}, errors.WithStack(errors.New("login invalid"))
	}

	if !IsSignIn {
		if email == "" {
			return structs.User{}, errors.WithStack(errors.New("email not exist"))
		}
		if !emailRegex.MatchString(email) {
			return structs.User{}, errors.WithStack(errors.New("email invalid"))
		}
	}

	if !IsPasswordReset {
		if password == "" {
			return structs.User{}, errors.WithStack(errors.New("password not exist"))
		}
		if !passwordRegex.MatchString(password) {
			return structs.User{}, errors.WithStack(errors.New("password invalid"))
		}
	}

	return validatedLoginInput, nil
}
