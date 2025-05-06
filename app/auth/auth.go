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
	"github.com/gimaevra94/auth/app/logtraceredir"
	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(logout.IsExpiredTokenMW(store))

	r.Get(consts.SignUpURL, signUpLoginInput)
	r.Post(consts.InputCheckURL, inputCheck)
	r.Get(consts.CodeSendURL, codeSend)
	r.Post(consts.UserAddURL, userAdd)

	r.Get(consts.SignInURL, signInLoginInput)

	r.Get(consts.RequestErrorURL, requestError)

	r.With(logout.IsExpiredTokenMW(store)).Post(consts.LogInURL, logIn)
	r.With(logout.IsExpiredTokenMW(store)).Get(consts.HomeURL, Home)
	r.With(logout.IsExpiredTokenMW(store)).Post(consts.LogoutURL, logOut)

	return r
}

func signUpLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.SignUpLoginInputHTML)
}

func requestError(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.SignUpLoginInputHTML)
}

func inputCheck(w http.ResponseWriter, r *http.Request) {
	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		// проверить как будте выглядеть ошибка
		logtraceredir.LogTraceRedir(w, r,
			err, "", consts.RequestErrorURL, true)
	}

	err = database.UserCheck(w, r, validatedLoginInput, true)
	if err != nil {
		if err == sql.ErrNoRows {
			err := sessionUserSetMarshal(w, r, store, validatedLoginInput)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				validator.LogTraceAndRedirectErr(w, r,
					err, "", "/request_error", true)
			}
			http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		}

		http.ServeFile(w, r, consts.RequestErrorHTML)
		validator.LogTraceAndRedirectErr(w, r, err, "", "request_error", true)
	}

	http.ServeFile(w, r, consts.UserAlreadyExistHTML)
	validator.LogTraceAndRedirectErr(w, r, "already exist", "user", "/already_exist", true)
}

func codeSend(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.CodeSendHTML)
	session, user, err := sessionUserGetUnmarshal(r, store)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserGetFromSessionErr, err)
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
	session, user, err := sessionUserGetUnmarshal(r, store)
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

	err = database.UserAdd(w, r, user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserAddInDBFailedErr, err)
	}

	tokenExp := r.FormValue(consts.RememberStr)
	err = tokenizer.TokenCreate(w, r, tokenExp, user)
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

	lastActivity := time.Now().Add(consts.TokenLifetime3HoursInt)
	session.Values[consts.LastActivityStr] = lastActivity
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
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

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, consts.HomeHTML)
}

func logOut(w http.ResponseWriter, r *http.Request) {
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
		Name:     consts.CookieNameStr,
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

func sessionUserGetUnmarshal(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, structs.User, error) {

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		log.Println(consts.SessionGetFailedErr, err)
		return nil, nil, err
	}

	jsonData, ok := session.Values[consts.UserStr].([]byte)
	if !ok {
		log.Println(consts.UserNotExistInSessionErr)
		return nil, nil, err
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		log.Println(consts.UserDeserializeFailedErr, err)
		return nil, nil, err
	}

	return session, user, nil
}

func sessionUserSetMarshal(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore, user structs.User) error {

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		log.Println(consts.SessionGetFailedErr, err)
		return err
	}
	jsonData, err := json.Marshal(user)
	if err != nil {
		log.Println(consts.UserSerializeFailedErr, err)
		return err
	}

	session.Values[consts.UserStr] = jsonData
	err = session.Save(r, w)
	if err != nil {
		log.Println(consts.UserSaveInSessionFailedErr, err)
		return err
	}
	return nil
}
