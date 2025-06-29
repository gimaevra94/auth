package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(w http.ResponseWriter, r *http.Request) {
	rememberMe := r.FormValue("rememberMe")
	if rememberMe == "" {
		log.Printf("%+v", errors.WithStack(errors.New("rememberMe: "+data.NotExistErr)))
		http.Redirect(w, r, data.Err500URL, http.StatusFound)
		return
	}

	validatedLoginInput, err := tools.IsValidInput(r, true)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, data.BadSignInURL, http.StatusFound)
		return
	}

	err = data.UserCheck2("login", validatedLoginInput.Login, validatedLoginInput.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.UserNotExistURL, http.StatusFound)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.BadSignInURL, http.StatusFound)
			return
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
		return
	}

	err = tools.TokenCreate(w, r, rememberMe, validatedLoginInput)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
		return
	}

	if rememberMe == "false" {
		lastActivity := time.Now().Add(3 * time.Hour)
		err := tools.SessionDataSet(w, r, lastActivity)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, data.HomeURL, http.StatusFound)
}
