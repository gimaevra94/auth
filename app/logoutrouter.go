package router

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

func LogoutRouter() {
	// основные переходы
	http.HandleFunc("/email_entry", router.EmailEntry)
	http.HandleFunc("/email_send", router.CodeSend)
	http.HandleFunc("/code_send", router.CodeCheck)
	// кнопки возврата
	http.HandleFunc("/back_to_mail_input", router.EmailEntry)
	http.HandleFunc("/back_to_code_input", router.CodeInput)
	http.HandleFunc("/code_not_arrived", router.CodeInput)
	http.HandleFunc("/token_entry", router.TokenEntry)
	http.HandleFunc("/sign_up", router.SignUp)
	http.HandleFunc("/singn_up_data_sending", router.SignUpDataSending)
	http.HandleFunc("/sign_in", router.SignIn)
	http.HandleFunc("/sign_in_data_sending", router.SignInDataSending)
	http.HandleFunc("/back_to_sign_up", router.SignUp)
	http.HandleFunc("/back_to_sign_in", router.SignIn)
}

const sessionDuration = 60 * time.Minute

var (
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
)

func LogoutTimer(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	ResetSession(w, r)
}

func ResetSession(w http.ResponseWriter, r *http.Request) {
	headerToken := r.Header.Get("Authrization")
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(headerToken, claims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
	if err != nil || token.Valid {
		http.ServeFile(w, r, "sign-in.html")
	}
	exp := int64((*claims)["exp"].(float64))
	if time.Now().Unix() > exp {
		http.ServeFile(w, r, "sign-in.html")
		return
	}
	if cancel != nil {
		cancel()
	}
	ctx, cancel = context.WithTimeout(context.Background(), sessionDuration)
	go func(w http.ResponseWriter, r *http.Request) {
		<-ctx.Done()
		mu.Lock()
		defer mu.Unlock()
	}(w, r)
}
