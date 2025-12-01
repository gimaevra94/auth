// Package errs предоставляет утилиты для обработки ошибок.
//
// Файл содержит функции для логирования и перенаправления при ошибках:
//   - LogAndRedirectIfErrNotNill: логирует ошибку и выполняет перенаправление
package errs

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
)

// LogAndRedirectIfErrNotNill обрабатывает ошибку, логирует её и выполняет перенаправление.
//
// Логирует ошибку с полным стеком вызовов и перенаправляет пользователя на указанный URL.
// Если URL пустой или равен "/", перенаправляет на страницу ошибки 500.
func LogAndRedirectIfErrNotNill(w http.ResponseWriter, r *http.Request, err error, url string) {
	log.Printf("%+v", err)
	if url == "" || url == "/" {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	} else {
		http.Redirect(w, r, url, http.StatusFound)
		return
	}
}
