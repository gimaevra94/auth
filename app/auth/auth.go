package auth

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/logout"
	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))
var userAddFromLogIn bool

func Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(logout.IsExpiredTokenMW(store))

	r.Get(consts.SignUpURL, signUpLoginInput)
	r.Post(consts.InputCheckURL, inputCheck)
	r.Get(consts.CodeSendURL, codeSend)
	r.Post(consts.UserAddURL, userAdd)

	r.Get(consts.SignInURL, signInLoginInput)
	r.With(logout.IsExpiredTokenMW(store)).Post(consts.LogInURL, logIn)

	r.With(logout.IsExpiredTokenMW(store)).Get(consts.HomeURL, Home)
	r.With(logout.IsExpiredTokenMW(store)).Post(consts.LogoutURL, Logout)

	return r
}

func signUpLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.SignUploginInput)
}

func inputCheck(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionGetFailedErr, err)
	}

	if session.Values[consts.UserStr] != nil {
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
	}

	user, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.InputValidateFailedErr, err)
	}

	err = database.UserCheck(w, r, user, !userAddFromLogIn)
	if err != nil {
		if err == sql.ErrNoRows {
			jsonData, err := json.Marshal(user)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.UserSerializeFailedErr, err)
			}

			session.Values[consts.UserStr] = jsonData
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.UserSaveInSessionFailedErr, err)
			}

			http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		}
	}

	http.ServeFile(w, r, consts.UserAllreadyExistHTML)
}

func codeSend(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.CodeSendHTML)
	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionGetFailedErr, err)
	}

	jsonData, ok := session.Values[consts.UserStr].([]byte)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserNotExistInSessionErr, err)
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserDeserializeFailedErr, err)
	}

	email := user.GetEmail()
	msCode, err := mailsendler.MailSendler(email)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.MailSendlerFailedErr, err)
	}

	session.Values[consts.MscodeStr] = msCode
	err = session.Save(r, w)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.MscodeSaveInSessionFailedErr, err)
	}
}

func userAdd(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionGetFailedErr, err)
	}

	userCode := r.FormValue(consts.UserCodeStr)
	msCode, ok := session.Values[consts.MscodeStr].(string)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.MscodeNotExistInSessionErr)
	}

	if userCode != msCode {
		http.ServeFile(w, r, consts.WrongCodeHTML)
		log.Println(consts.CodesNotMatchErr)
	}

	jsonData, ok := session.Values[consts.UserStr].([]byte)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserNotExistInSessionErr)
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserDeserializeFailedErr, err)
	}

	err = database.UserAdd(w, r, user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserAddInDBFailedErr, err)
	}

	tokenExp := r.FormValue(consts.RememberStr)
	err = tokenizer.TokenCreate(w, r, tokenExp, session)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.TokenCreateFailedErr, err)
	}

	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values[consts.LastActivityStr] = lastActivity

	Home(w, r)
}

func signInLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.SignInloginInputHTML)
}

func logIn(w http.ResponseWriter, r *http.Request) {
	rememberBool := r.FormValue(consts.RememberStr)
	if rememberBool == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.RememberGetInFormFailedErr)
	}

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionGetFailedErr, err)
	}

	var user structs.User
	if session.Values[consts.UserStr] != nil {
		jsonData, ok := session.Values[consts.UserStr].(string)
		if !ok {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println(consts.UserNotExistInSessionErr)
		}

		err := json.Unmarshal([]byte(jsonData), &user)
		if err != nil {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println(consts.UserDeserializeFailedErr, err)
		}
	}

	user, err = validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.InputValidateFailedErr, err)
	}

	err = database.UserCheck(w, r, user,
		userAddFromLogIn)
	if err != nil {
		if err == sql.ErrNoRows {
			http.ServeFile(w, r, consts.UserNotExistHTML)
			log.Println(consts.UserNotExistInDBErr, err)
		}
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.DBQueryExecuteFailedErr, err)
	}

	tokenExp := r.FormValue(consts.RememberStr)
	err = tokenizer.TokenCreate(w, r, tokenExp, session)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.TokenCreateFailedErr)
	}

	lastActivity := time.Now().Add(consts.TokenLifetime3HoursInt)
	session.Values[consts.LastActivityStr] = lastActivity
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.HomeHTML)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionGetFailedErr, err)
	}

	delete(session.Values, consts.LastActivityStr)
	err = session.Save(r, w)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.SessionSaveFailedErr, err)
	}

	cookie := http.Cookie{
		Name:     consts.AuthCookieNameStr,
		Path:     consts.AuthCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    consts.EmptyValueStr,
		MaxAge:   -1,
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, consts.LogoutURL, http.StatusFound)
}
