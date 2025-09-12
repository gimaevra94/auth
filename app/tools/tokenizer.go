package tools

import (
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, rememberMe string, user User) (string, error) {
	var exp int64

	switch rememberMe {
	case "true":
		exp = int64(24 * time.Hour)
	case "3hours":
		exp = int64(3 * time.Hour)
	default:
		exp = consts.NoExpiration
	}

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

func ResetTokenCreate() (string, error) {
	resetToken := make([]byte, 32)
	_, err := rand.Read(resetToken)
	if err != nil {
		return "", errors.WithStack(err)
	}
	encodeResetToken:=
	return string(resetToken), nil
}
