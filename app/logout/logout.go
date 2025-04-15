package logout

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
)

func IsExpiredTokenMW() func (http.Handler) http.Handler  {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				cookie,err:=r.Cookie("Authorization")
				if err!=nil{
					http.ServeFile(w,r,"logout.html")
					log.Println()
					return
				}

token:=cookie.Value
if token==""{
	http.ServeFile(w,r,consts.RequestErrorHTML)
	return
}

token,err:=jwt.Parse(token,GetJWTSecret)
if err!=nil{

}
							}
	)
			}
} {
	
}


