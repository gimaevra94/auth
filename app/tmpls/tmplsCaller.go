// Package tmpls предоставляет функции и шаблоны для рендеринга HTML-страниц.
//
// Файл содержит обработчики для рендеринга страниц приложения:
//   - SignUp: страница регистрации
//   - SignIn: страница входа
//   - ServerAuthCodeSend: страница отправки кода сервера
//   - Home: главная страница
//   - Logout: страница выхода
//   - GeneratePasswordResetLink: страница генерации ссылки сброса пароля
//   - SetNewPassword: страница установки нового пароля
//   - Err500: страница ошибки 500
package tmpls

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
)

// SignUp отображает страницу регистрации.
//
// Рендерит шаблон signUp с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
var SignUp = func(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "signUp", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// SignIn отображает страницу входа.
//
// Рендерит шаблон signIn с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
func SignIn(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "signIn", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// ServerAuthCodeSend отображает страницу отправки кода сервера.
//
// Рендерит шаблон serverAuthCodeSend с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
func ServerAuthCodeSend(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "serverAuthCodeSend", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// Home отображает главную страницу.
//
// Рендерит шаблон home с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
func Home(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "home", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// Logout отображает страницу выхода.
//
// Рендерит шаблон logout с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
func Logout(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "logout", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// GeneratePasswordResetLink отображает страницу генерации ссылки сброса пароля.
//
// Принимает параметр msg из URL query и передает его в шаблон.
// Рендерит шаблон generatePasswordResetLink с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
func GeneratePasswordResetLink(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	data := structs.MsgForUser{Msg: msg}
	if err := TmplsRenderer(w, BaseTmpl, "generatePasswordResetLink", data); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// SetNewPassword отображает страницу установки нового пароля.
//
// Принимает параметры msg и token из URL query и передает их в шаблон.
// Рендерит шаблон setNewPassword с базовым шаблоном BaseTmpl.
// В случае ошибки логирует и перенаправляет на страницу 500.
func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Msg   string
		Token string
	}{Msg: r.URL.Query().Get("msg"), Token: r.URL.Query().Get("token")}
	if err := TmplsRenderer(w, BaseTmpl, "setNewPassword", data); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

// Err500 отображает страницу ошибки 500.
//
// Отправляет статический файл 500.html клиенту.
func Err500(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../public/500.html")
}
