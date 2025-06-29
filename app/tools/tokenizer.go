package tools

import (
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/data"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, exp int64,
	user data.User) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  exp,
	})

	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", errors.WithStack(err)
	}

	return SignedToken, nil
}
