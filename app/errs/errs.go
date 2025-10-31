package errs

import (
	"log"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
)

func LogAndRedirectIfErrNotNill(w http.ResponseWriter, r *http.Request, err error, url string) {
	if err != nil {
		log.Printf("%v", err)

		if url == "" || !strings.HasPrefix(r.URL.Path, "/") {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		http.Redirect(w, r, url, http.StatusFound)
		return
	}
}
