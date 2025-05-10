package signin

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(w http.ResponseWriter, r *http.Request) {
	rememberBool := r.FormValue(consts.RememberStr)
	if rememberBool == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.RememberGetInFormFailedErr)
	}

	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.InputValidateFailedErr, err)
	}

	err = database.UserCheck(w, r, validatedLoginInput, true)
	if err != nil {
		if err == sql.ErrNoRows {
			http.ServeFile(w, r, consts.UserNotExistHTML)
			log.Println(consts.UserNotExistInDBErr, err)
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			http.ServeFile(w, r, consts.BadSignInHTML)
		}
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.DBQueryExecuteFailedErr, err)
	}

	tokenExp := r.FormValue(consts.RememberStr)
	err = tokenizer.TokenCreate(w, r, tokenExp, validatedLoginInput)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.TokenCreateFailedErr, err)
	}

	cookie, err := r.Cookie(consts.CookieNameStr)
	if err != nil {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	}
	w.Header().Set(consts.CookieNameStr, consts.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionGetFailedErr, err)
	}

	lastActivity := time.Now().Add(consts.TokenLifetime3HoursInt)
	session.Values[consts.LastActivityStr] = lastActivity
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
