package tmpls

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	show := false
	// Предпочитаем проверку по БД: если у текущего пользователя пароль ещё НЕ задан (passwordHash IS NULL), показываем кнопку.
	if tempCookies, err := data.GetTemporaryUserIdFromCookies(r); err == nil && tempCookies != nil {
		var login, email, permanentUserId string
		if err := data.Db.QueryRow(consts.PasswordSetQuery, tempCookies.Value).Scan(&login, &email, &permanentUserId); err == nil {
			// Запись найдена -> passwordHash IS NULL -> показываем кнопку
			show = true
		} else if err != sql.ErrNoRows {
			// В случае ошибки БД не ломаем UX, логируем и используем запасную проверку по куке yauth
			log.Printf("Home: PasswordSetQuery error: %+v", err)
			if c, cerr := r.Cookies("yauth"); cerr == nil && c != nil && c.Value == "1" {
				show = true
			}
		}
	} else {
		// Если нет temp Cookies, откатываемся к прежней логике по куке yauth
		if c, err := r.Cookies("yauth"); err == nil && c != nil && c.Value == "1" {
			show = true
		}
	}
	data := struct{ ShowSetPassword bool }{ShowSetPassword: show}
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "Home", data)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "Logout", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func PasswordReset(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: msg})
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	msg := r.URL.Query().Get("msg")
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", struct {
		Msg   string
		Token string
	}{Msg: msg, Token: token})
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func SetFirstTimePassword(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	data := struct {
		Msg  string
		Regs []string
	}{
		Msg:  msg,
		Regs: tools.PswrdReqs,
	}
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetFirstTimePassword", data)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func Err500(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../public/500.html")
}
