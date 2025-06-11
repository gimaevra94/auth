package errs

import (
	"log"
	"net/http"

	"github.com/pkg/errors"
)

func WrappedErrPrintRedir(w http.ResponseWriter, r *http.Request,
	path string, err error) {
	log.Printf("%+v", err)
	http.Redirect(w, r, path, http.StatusFound)
}

func OrigErrWrapPrintRedir(w http.ResponseWriter, r *http.Request,
	path string, err error) error {
	WithStackedErr := errors.WithStack(err)
	log.Printf("%+v", WithStackedErr)
	if path != "" {
		http.Redirect(w, r, path, http.StatusFound)
	}
	return WithStackedErr
}

func NewErrWrapPrintRedir(w http.ResponseWriter, r *http.Request,
	path string, err string, key string) error {
	newErr := errors.New(key + ": " + err)
	wrappedErr := errors.WithStack(newErr)
	log.Printf("%+v", wrappedErr)
	if path != "" {
		http.Redirect(w, r, path, http.StatusFound)
	}
	return wrappedErr
}
