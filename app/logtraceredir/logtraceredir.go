package logtraceredir

import (
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/pkg/errors"
)

var validPathRegex = regexp.MustCompile(`^/[a-zA-Z0-9_/\\-]+$`)

func LogTraceRedir(w http.ResponseWriter, r *http.Request,
	err interface{}, key string, path string, isExternalCall bool) error {
	if err == nil {
		log.Printf("'err' is nil")
		return nil
	}

	if isExternalCall {
		if e, ok := err.(error); ok {
			if !validPathRegex.MatchString(path) {
				log.Println("path format must be like '/sign_in'")
				return nil
			}

			log.Printf("%+v\n", e)
			http.Redirect(w, r, path, http.StatusFound)
			return nil
		}

		log.Printf("excpected 'error' type for 'err' when 'isExternalCall' = true, got: %T", err)
		return nil
	}

	switch e := err.(type) {
	case error, string:
		if key == "" {
			key = "'key' not set"
		}

		wrappedErr := errors.Wrapf(errors.New(fmt.Sprintf("%v", e)), key)
		log.Printf("%+v\n", wrappedErr)
		return wrappedErr
	}

	log.Printf("excpected 'error' or 'string' type for 'err' when 'isExternalCall' = false, got: %T", err)
	return nil
}
