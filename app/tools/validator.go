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

func RefreshTokenValidator(refreshToken string) error {
	signedToken, err := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
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

/*func AccessTokenValidator(token string) (*structs.AccessTokenClaims, error) {

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
}*/

func InputValidator(r *http.Request, login, email, password string, IsSignIn, IsPasswordReset bool) error {

	if login == "" {
		return errors.WithStack(errors.New("login not exist"))
	}
	if !loginRegex.MatchString(login) {
		return errors.WithStack(errors.New("login invalid"))
	}

	if !IsSignIn {
		if email == "" {
			return errors.WithStack(errors.New("email not exist"))
		}
		if !emailRegex.MatchString(email) {
			return errors.WithStack(errors.New("email invalid"))
		}
	}

	if !IsPasswordReset {
		if password == "" {
			return errors.WithStack(errors.New("password not exist"))
		}
		if !passwordRegex.MatchString(password) {
			return errors.WithStack(errors.New("password invalid"))
		}
	}

	return nil
}

func CodeValidator(r *http.Request, clientCode, serverCode string) error {
	if clientCode == "" {
		return errors.WithStack(errors.New("clientCode not exist"))
	}

	if clientCode != serverCode {
		return errors.WithStack(errors.New("codes not match"))
	}
	return nil
}
