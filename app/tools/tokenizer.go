package tools

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, command string,
	value app.User) error {

	var token *jwt.Token
	user := value.GetLogin()

	switch command {
	case "false":
		exp := time.Now().Add(24 * time.Hour)
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})

	case "true":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
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
		wrappedErr := errors.WithStack(err)
		log.Println("%+v", wrappedErr)
		return err
	}

	cookie := http.Cookie{
		Name:     "auth",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    SignedToken,
	}

	http.SetCookie(w, &cookie)
	w.Header().Set("auth", cookie.Value)
	w.Write([]byte(cookie.Value))

	return nil
}
