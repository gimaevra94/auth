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
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

type SignUpPageData struct {
	Msg         string
	CaptchaShow bool
}

func SignUpInputCheck(w http.ResponseWriter, r *http.Request) {
	var user structs.User

	var captchaShow bool

	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	user = structs.User{
		Login:    login,
		Email:    email,
		Password: password,
	}

	captchaCounter, err := data.SessionCaptchaCounterGet(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			log.Printf("DEBUG: SignUpInputCheck - captchaCounter initialized to 3 (session not exist)")
		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	} else {
		log.Printf("DEBUG: SignUpInputCheck - Retrieved captchaCounter from session: %d", captchaCounter)
	}

	sessionCaptchaShow, err := data.SessionCaptchaShowGet(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaShow = false
			log.Printf("DEBUG: SignUpInputCheck - captchaShow initialized to false (session not exist)")
		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	} else {
		captchaShow = sessionCaptchaShow
		log.Printf("DEBUG: SignUpInputCheck - Retrieved captchaShow from session: %t", captchaShow)
	}

	err = tools.InputValidate(r, user.Login, user.Email, user.Password, false)
	if err != nil {
		log.Printf("DEBUG: SignUpInputCheck - Input validation failed: %v", err)
		if strings.Contains(err.Error(), "login") {
			log.Printf("DEBUG: SignUpInputCheck - Handling login error. captchaCounter before decrement: %d", captchaCounter)
			err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			log.Printf("DEBUG: SignUpInputCheck - captchaCounter decremented and saved to session: %d", captchaCounter-1)

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
				log.Printf("DEBUG: SignUpInputCheck - captchaCounter hit 0, setting captchaShow to true: %t", captchaShow)

				err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				log.Printf("DEBUG: SignUpInputCheck - captchaShow saved to session: %t", captchaShow)
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["login"].Msg, CaptchaShow: captchaShow})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return

		} else if strings.Contains(err.Error(), "email") {
			log.Printf("DEBUG: SignUpInputCheck - Handling email error. captchaCounter before decrement: %d", captchaCounter)
			err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			log.Printf("DEBUG: SignUpInputCheck - captchaCounter decremented and saved to session: %d", captchaCounter-1)

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
				log.Printf("DEBUG: SignUpInputCheck - captchaCounter hit 0, setting captchaShow to true: %t", captchaShow)

				err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				log.Printf("DEBUG: SignUpInputCheck - captchaShow saved to session: %t", captchaShow)
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["email"].Msg, CaptchaShow: captchaShow})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return

		} else if strings.Contains(err.Error(), "password") {
			log.Printf("DEBUG: SignUpInputCheck - Handling password error. captchaCounter before decrement: %d", captchaCounter)
			err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			log.Printf("DEBUG: SignUpInputCheck - captchaCounter decremented and saved to session: %d", captchaCounter-1)

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
				log.Printf("DEBUG: SignUpInputCheck - captchaCounter hit 0, setting captchaShow to true: %t", captchaShow)

				err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				log.Printf("DEBUG: SignUpInputCheck - captchaShow saved to session: %t", captchaShow)
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["password"].Msg, CaptchaShow: captchaShow})
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

	log.Printf("DEBUG: SignUpInputCheck - Input validation successful.")
	err = data.AuthSessionDataSet(w, r, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	log.Printf("DEBUG: SignUpInputCheck - Resetting captchaCounter to 3 and captchaShow to false after successful input.")
	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", 3) // При успешной валидации сбрасываем счетчик
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.CaptchaSessionDataSet(w, r, "captchaShow", false) // Скрываем капчу
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	SignUpUserCheck(w, r)
}

func SignUpUserCheck(w http.ResponseWriter, r *http.Request) {
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
	} else {
		log.Printf("DEBUG: SignUpUserCheck - Retrieved captchaCounter from session: %d", captchaCounter)
	}

	captchaShow, err := data.SessionCaptchaShowGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	} else {
		log.Printf("DEBUG: SignUpUserCheck - Retrieved captchaShow from session: %t", captchaShow)
	}

	_, err = data.UserCheck(user.Login, user.Password)
	if err != nil {
		log.Printf("DEBUG: SignUpUserCheck - UserCheck failed: %v", err)
		if errors.Is(err, sql.ErrNoRows) {
			CodeSend(w, r)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("DEBUG: SignUpUserCheck - Handling bcrypt.ErrMismatchedHashAndPassword. captchaCounter before decrement: %d", captchaCounter)
			if captchaCounter == 0 {
				captchaShow = true
				log.Printf("DEBUG: SignUpUserCheck - captchaCounter hit 0, setting captchaShow to true: %t", captchaShow)
			}
			captchaCounter -= 1
			log.Printf("DEBUG: SignUpUserCheck - captchaCounter after decrement: %d", captchaCounter)

			// Сохраняем обновленные значения в сессию
			err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			log.Printf("DEBUG: SignUpUserCheck - captchaCounter saved to session: %d", captchaCounter)
			err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			log.Printf("DEBUG: SignUpUserCheck - captchaShow saved to session: %t", captchaShow)

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["password"].Msg, CaptchaShow: captchaShow})
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

	log.Printf("DEBUG: SignUpUserCheck - UserCheck successful or user already exists. captchaCounter before decrement: %d", captchaCounter)
	if captchaCounter == 0 {
		captchaShow = true
		log.Printf("DEBUG: SignUpUserCheck - captchaCounter hit 0, setting captchaShow to true: %t", captchaShow)
	}
	captchaCounter -= 1
	log.Printf("DEBUG: SignUpUserCheck - captchaCounter after decrement: %d", captchaCounter)

	// Сохраняем обновленные значения в сессию
	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	log.Printf("DEBUG: SignUpUserCheck - captchaCounter saved to session: %d", captchaCounter)
	err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	log.Printf("DEBUG: SignUpUserCheck - captchaShow saved to session: %t", captchaShow)

	err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["alreadyExist"].Msg, CaptchaShow: captchaShow})
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	// Удалил закомментированные строки, так как они дублировали функционал сохранения сессии выше.
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	serverCode, err := tools.AuthCodeSend(user.Email)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	user.ServerCode = serverCode

	err = data.AuthSessionDataSet(w, r, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if r.URL.Path != "/code-send" && r.URL.Path != "/password-reset" {
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		return
	}
}

func UserAdd(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	clientCode := r.FormValue("clientCode")
	err = tools.CodeValidate(r, clientCode, user.ServerCode)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		err = tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.ErrMsg["serverCode"])
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	temporaryUserID := uuid.New().String()
	permanentUserID := uuid.New().String()
	temporaryCancelled := false

	err = data.UserAdd(user.Login, user.Email, user.Password, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	tokenCancelled := false
	err = data.RefreshTokenAdd(permanentUserID, refreshToken, r.UserAgent(), tokenCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaCounter := 3
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
