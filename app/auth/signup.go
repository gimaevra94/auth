package auth

import (
	"app/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/app"
	"github.com/gimaevra94/auth/app/tools"
)

func InputCheck(w http.ResponseWriter, r *http.Request) {
	validatedLoginInput, err := tools.IsValidInput(w, r)
	if err != nil {
		logtraceredir.LogTraceRedir(w, r,
			err, "", app.RequestErrorURL, true)
	}

	err = app.UserCheck(w, r, validatedLoginInput, true)
	if err != nil {
		if err == sql.ErrNoRows {
			err := tools.SessionUserSetMarshal(w, r, store, validatedLoginInput)
			if err != nil {
				logtraceredir.LogTraceRedir(w, r,
					err, "", app.RequestErrorURL, true)
			}
			http.Redirect(w, r, app.CodeSendURL, http.StatusFound)
		}

		http.ServeFile(w, r, app.RequestErrorHTML)
		tools.LogTraceAndRedirectErr(w, r, err, "", "request_error", true)
	}

	http.ServeFile(w, r, app.UserAlreadyExistHTML)
	tools.LogTraceAndRedirectErr(w, r, "already exist", "user", "/already_exist", true)
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, app.CodeSendHTML)
	session, user, err := tools.SessionUserGetUnmarshal(r, store)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.UserGetFromSessionErr, err)
	}

	email := user.GetEmail()
	msCode, err := tools.MailSendler(email)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.MailSendlerFailedErr, err)
	}

	session.Values[app.MscodeStr] = msCode
	err = session.Save(r, w)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.MscodeSaveInSessionFailedErr, err)
	}
}

func UserAdd(w http.ResponseWriter, r *http.Request) {
	session, user, err := tools.SessionUserGetUnmarshal(r, store)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.SessionGetFailedErr, err)
	}

	userCode := r.FormValue(app.UserCodeStr)
	msCode, ok := session.Values[app.MscodeStr].(string)
	if !ok {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.MscodeNotExistInSessionErr)
	}

	if userCode != msCode {
		http.ServeFile(w, r, app.WrongCodeHTML)
		log.Println(app.CodesNotMatchErr)
	}

	err = app.UserAdd(w, r, user)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.UserAddInDBFailedErr, err)
	}

	tokenExp := r.FormValue(app.RememberStr)
	err = tools.TokenCreate(w, r, tokenExp, user)
	if err != nil {
		http.ServeFile(w, r, app.RequestErrorHTML)
		log.Println(app.TokenCreateFailedErr, err)
	}

	cookie, err := r.Cookie(app.CookieNameStr)
	if err != nil {
		http.Redirect(w, r, app.SignUpURL, http.StatusFound)
	}
	w.Header().Set(app.CookieNameStr, app.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))

	lastActivity := time.Now().Add(app.TokenLifetime3HoursInt)
	session.Values[app.LastActivityStr] = lastActivity
	http.Redirect(w, r, app.HomeURL, http.StatusFound)
}
