package tools

import (
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, command string,
	user data.User) error {

	var token *jwt.Token

	switch command {
	case "false":
		exp := time.Now().Add(24 * time.Hour).Unix()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})

	case "true":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  253402300799,
		})

	case "3hours":
		exp := time.Now().Add(3 * time.Hour)
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})
	}

	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return errors.WithStack(err)
	}

	dataCookie := data.NewCookie()
	dataCookie.SetValue(SignedToken)
	httpCookie := dataCookie.GetCookie()
	http.SetCookie(w, httpCookie)

	return nil
}
