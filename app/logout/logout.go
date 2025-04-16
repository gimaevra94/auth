package logout

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/golang-jwt/jwt"
)

func IsExpiredTokenMW() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {
validator.IsValidToken(r)
validator.GetNewToken(r)


		})
	}
}
