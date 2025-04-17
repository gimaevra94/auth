package logout

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
)

func IsExpiredTokenMW() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {
			err := validator.IsValidToken(r)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Token validation is failed", err)
				return
			}

			tokenizer.TokenCreate(w,"expire_3_hours")

		})
	}
}
