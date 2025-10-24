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
	NoPassword         bool // Новое поле для передачи флага
}

func SignInInputCheck(w http.ResponseWriter, r *http.Request) {
	log.Printf("[SignInInputCheck] Начало выполнения")
	var user structs.User
	var captchaShow bool
	captchaCounter := int64(3)
	login := r.FormValue("login")
	password := r.FormValue("password")
	user = structs.User{
		Login:    login,
		Password: password,
	}
	// Инициализация/чтение состояния капчи из сессии
	if cnt, err := data.SessionCaptchaCounterGet(r); err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			_ = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter)
		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	} else {
		captchaCounter = cnt
	}

	if show, err := data.SessionCaptchaShowGet(r); err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaShow = false
			_ = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	} else {
		captchaShow = show
	}

	// Если капча уже должна показываться — проверяем её до валидации инпутов
	if captchaShow {
		if err := tools.Captcha(r); err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") {
				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["captchaRequired"].Msg, CaptchaShow: captchaShow, Regs: nil})
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				return
			}
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}
	err := tools.InputValidate(r, user.Login, "", user.Password, true)
	if err != nil {
		log.Printf("[SignInInputCheck] Ошибка валидации: %v", err)
		if strings.Contains(err.Error(), "login") {
			// уменьшаем счетчик и сохраняем
			if err2 := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1); err2 != nil {
				log.Printf("%+v", err2)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
				if err2 := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err2 != nil {
					log.Printf("%+v", err2)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
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
				// уменьшаем счетчик и сохраняем
				if err2 := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1); err2 != nil {
					log.Printf("%+v", err2)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				captchaCounter -= 1
				if captchaCounter == 0 {
					captchaShow = true
					if err2 := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err2 != nil {
						log.Printf("%+v", err2)
						http.Redirect(w, r, consts.Err500URL, http.StatusFound)
						return
					}
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
	// На этом этапе не трогаем счетчик — он уже актуален в сессии
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
			log.Printf("[SignInUserCheck] У пользователя NULL пароль, отображение сообщения на странице входа")
			// Передаем флаг NoPassword в шаблон SignIn
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{NoPassword: true})
			if err != nil {
				log.Printf("[SignInUserCheck] Ошибка рендера страницы входа с сообщением NoPassword: %+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("[SignInUserCheck] Пользователь не найден, отображение ошибки")
			if err2 := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1); err2 != nil {
				log.Printf("%+v", err2)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
				if err2 := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err2 != nil {
					log.Printf("%+v", err2)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
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
			if err2 := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1); err2 != nil {
				log.Printf("%+v", err2)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
				if err2 := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err2 != nil {
					log.Printf("%+v", err2)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
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
	// Помечаем, что вход НЕ через Яндекс (чтобы скрывать кнопку Set Password)
	http.SetCookie(w, &http.Cookie{
		Name:     "yauth",
		Value:    "0",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIDExp,
	})
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
	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	// Сбрасываем флаг показа капчи
	if err = data.CaptchaSessionDataSet(w, r, "captchaShow", false); err != nil {
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

// ... (остальные функции остаются без изменений)
