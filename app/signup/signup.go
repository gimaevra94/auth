package signup

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/logtraceredir"
	mailsendler "github.com/gimaevra94/auth/app/mailsender"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
)

func InputCheck(w http.ResponseWriter, r *http.Request) {
	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		logtraceredir.LogTraceRedir(w, r,
			err, "", consts.RequestErrorURL, true)
	}

	err = database.UserCheck(w, r, validatedLoginInput, true)
	if err != nil {
		if err == sql.ErrNoRows {
			err := SessionUserSetMarshal(w, r, store, validatedLoginInput)
			if err != nil {
				logtraceredir.LogTraceRedir(w, r,
					err, "", consts.RequestErrorURL, true)
			}
			http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		}

		http.ServeFile(w, r, consts.RequestErrorHTML)
		validator.LogTraceAndRedirectErr(w, r, err, "", "request_error", true)
	}

	http.ServeFile(w, r, consts.UserAlreadyExistHTML)
	validator.LogTraceAndRedirectErr(w, r, "already exist", "user", "/already_exist", true)
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
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

func UserAdd(w http.ResponseWriter, r *http.Request) {
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


