package auth

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func PasswordResetEmailCheck(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	err := tools.EmailValidate(email)
	if err != nil {
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: tools.ErrMsg["email"].Msg})
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	err = data.PasswordResetEmailCheck(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: tools.ErrMsg["notExist"].Msg})
			if err != nil {
				log.Printf("%+v", errors.WithStack(err))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}

		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	baseURL := "http://localhost:8080/set-new-password"
	resetLink, err := tools.GenerateResetLink(email, baseURL)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Сохраняем reset-token в БД, чтобы последующая проверка прошла успешно
	// Токен берём из query параметра ссылки
	if u, perr := url.Parse(resetLink); perr == nil {
		token := u.Query().Get("token")
		if token != "" {
			tx, terr := data.DB.Begin()
			if terr != nil {
				log.Printf("%+v", errors.WithStack(terr))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
					panic(r)
				}
			}()
			defer tx.Rollback()

			if aerr := data.ResetTokenAddTx(tx, token); aerr != nil {
				log.Printf("%+v", errors.WithStack(aerr))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			if cerr := tx.Commit(); cerr != nil {
				log.Printf("%+v", errors.WithStack(cerr))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		}
	}

	err = tools.SendPasswordResetEmail(email, resetLink)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: "Не удалось отправить письмо. Проверьте адрес или позже попробуйте снова."})
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	// Успех: показываем понятное подтверждение
	if r.Method == http.MethodPost {
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: "Password reset link has been sent to your email."}); err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	signedToken := r.FormValue("token")
	if signedToken == "" {
		log.Println("reset-token not exist")
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	claims, err := tools.ValidateResetToken(signedToken)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	cancelled, err := data.ResetTokenCheck(signedToken)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	if cancelled {
		err := errors.New("reset-token invalid")
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	if newPassword != confirmPassword {
		log.Println("New password validation failed")
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", struct{ Msg string }{Msg: tools.ErrMsg["password"].Msg})
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		err = tools.PasswordValidate(newPassword)
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	tx, err := data.DB.Begin()
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()
	defer tx.Rollback()

	err = data.UpdatePasswordTx(tx, claims.Email, newPassword)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.ResetTokenCancelTx(tx, signedToken)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.SignInURL+"?msg=PasswordSuccessfullyReset", http.StatusFound)
}
