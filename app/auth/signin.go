package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(w http.ResponseWriter, r *http.Request) {
	rememberMe := r.FormValue("rememberMe")
	if rememberMe == "" {
		log.Printf("%+v", errors.WithStack(errors.New("rememberMe: "+tmpls.NotExistErr)))
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	validatedLoginInput, err := tools.IsValidInput(r, true)
	if err != nil {
		err = tools.ErrRenderer(w, tools.BaseTmpl, tmpls.MsCodeMsg, []string{})
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
			return
		}
		return
	}

	err = data.UserCheck("login", validatedLoginInput.Login, validatedLoginInput.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.UserNotExistURL, http.StatusFound)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.BadSignInURL, http.StatusFound)
			return
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	_, err = tools.TokenCreate(w, r, rememberMe, validatedLoginInput)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	if rememberMe == "false" {
		lastActivity := time.Now().Add(3 * time.Hour)
		err := data.SessionDataSet(w, r, "lastActivity", lastActivity)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, tmpls.HomeURL, http.StatusFound)
}
