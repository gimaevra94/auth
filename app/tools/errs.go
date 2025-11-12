package tools

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
)

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
