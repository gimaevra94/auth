package tools

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app"
	"github.com/golang-jwt/jwt"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, command string,
	value app.User) error {

	var token *jwt.Token
	user := value.GetLogin()

	switch command {
	case app.EmptyValueStr:
		exp := time.Now().Add(24 * time.Hour)
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			app.UserStr: user,
			app.ExpStr:  exp,
		})

	case app.OnValueStr:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			app.UserStr: user,
		})

	case app.TokenCommand3HoursStr:
		exp := time.Now().Add(app.TokenLifetime3HoursInt)
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			app.UserStr: user,
			app.ExpStr:  exp,
		})
	}

	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Println(app.TokenSignFailedErr, err)
		return err
	}

	cookie := http.Cookie{
		Name:     app.CookieNameStr,
		Path:     app.AuthCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    SignedToken,
	}

	http.SetCookie(w, &cookie)
	w.Header().Set(app.CookieNameStr, app.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))

	return nil
}
