package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type SignInPageData struct {
	Msg                string
	ShowForgotPassword bool
	CaptchaShow        bool
	Regs               []string
}

func SignInInputCheck(w http.ResponseWriter, r *http.Request) {
	log.Printf("[SignInInputCheck] Начало выполнения")
	var user structs.User
	var captchaShow bool

	captchaCounter := 3

	login := r.FormValue("login")
	password := r.FormValue("password")

	user = structs.User{
		Login:    login,
		Password: password,
	}

	err := tools.InputValidate(r, user.Login, "", user.Password, true)
	if err != nil {
		log.Printf("[SignInInputCheck] Ошибка валидации: %v", err)
		if strings.Contains(err.Error(), "login") {
			if captchaCounter-1 <= 0 {
				captchaShow = true
			}

			log.Printf("[SignInInputCheck] Отображение ошибки валидации логина")
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["login"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["login"].Regs})
			if err != nil {
				log.Printf("[SignInInputCheck] Ошибка рендера страницы входа после невалидного логина: %+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return

		} else {
			if strings.Contains(err.Error(), "password") {
				if captchaCounter-1 <= 0 {
					captchaShow = true
				}

				log.Printf("[SignInInputCheck] Отображение ошибки валидации пароля (на этапе ввода)")
				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["password"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["password"].Regs})
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				return
			}
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	log.Printf("[SignInInputCheck] Валидация пройдена, сохраняем данные в сессию")

	err = data.AuthSessionDataSet(w, r, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	log.Printf("[SignInInputCheck] Вызов SignInUserCheck")
	SignInUserCheck(w, r)
}

func SignInUserCheck(w http.ResponseWriter, r *http.Request) {
	log.Printf("[SignInUserCheck] Начало выполнения")
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaCounter, err := data.SessionCaptchaCounterGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaShow, err := data.SessionCaptchaShowGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	log.Printf("[SignInUserCheck] Проверка пользователя в БД: %s", user.Login)
	permanentUserID, err := data.UserCheck(user.Login, user.Password)
	if err != nil {
		log.Printf("[SignInUserCheck] Ошибка при проверке пользователя: %v", err)
		// Если у пользователя нет пароля (вход через внешнего провайдера),
		// отправляем на страницу установки пароля
		if strings.Contains(err.Error(), "password hash is NULL") {
			log.Printf("[SignInUserCheck] У пользователя NULL пароль, перенаправление на установку пароля")
			// Разрешаем переход на /set-password через сессионный флаг
			if session, sErr := data.LoginSessionGet(r); sErr == nil {
				session.Values["allowSetPassword"] = true
				_ = session.Save(r, w)
			}
			http.Redirect(w, r, consts.SetPasswordURL+"?msg=Please+set+your+password", http.StatusFound)
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("[SignInUserCheck] Пользователь не найден, отображение ошибки")
			if captchaCounter-1 <= 0 {
				captchaShow = true
			}
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["notExist"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["notExist"].Regs})
			if err != nil {
				log.Printf("[SignInUserCheck] Ошибка рендера страницы входа для несуществующего пользователя: %+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("[SignInUserCheck] Неверный пароль для существующего пользователя, отображение ошибки")
			if captchaCounter-1 <= 0 {
				captchaShow = true
			}
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["password"].Msg, ShowForgotPassword: true, CaptchaShow: captchaShow, Regs: tools.ErrMsg["password"].Regs})
			if err != nil {
				log.Printf("[SignInUserCheck] Ошибка рендера страницы входа для неверного пароля: %+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	log.Printf("[SignInUserCheck] Пользователь успешно аутентифицирован, создание сессии")

	temporaryUserID := uuid.New().String()
	data.TemporaryUserIDCookieSet(w, temporaryUserID)

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	tx, err := data.DB.Begin()
	if err != nil {
		log.Printf("%+v", err)
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

	err = data.TemporaryUserIDAddTx(tx, user.Login, temporaryUserID, false)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	tokenCancelled := false
	err = data.RefreshTokenAddTx(tx, permanentUserID, refreshToken, r.UserAgent(), tokenCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaCounter = 3
	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.AuthSessionEnd(w, r)
	if err != nil {
		log.Printf("%v", errors.WithStack(err))
		http.Redirect(w, r, consts.SignInURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
