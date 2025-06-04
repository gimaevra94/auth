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

func WithStackingErrPrintRedir(w http.ResponseWriter, r *http.Request,
	path string, err error) error {
	WithStackedErr := errors.WithStack(err)
	log.Printf("%+v", WithStackedErr)
	if path != "" {
		http.Redirect(w, r, path, http.StatusFound)
	}
	return WithStackedErr
}

func WrappingErrPrintRedir(w http.ResponseWriter, r *http.Request,
	path string, err string, key string) error {
	newErr := errors.New(err)
	wrappedErr := errors.Wrap(newErr, key)
	log.Printf("%+v", wrappedErr)
	if path != "" {
		http.Redirect(w, r, path, http.StatusFound)
	}
	return wrappedErr
}
