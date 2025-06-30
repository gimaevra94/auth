package tools

import (
	"html/template"
	"net/http"

	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/pkg/errors"
)

func Must(t *template.Template, err error) *template.Template {
	return template.Must(t, err)
}

var (
	BaseTmpl = Must(template.New("base").Parse(tmpls.BaseTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.SignUpTMPL))
)

func ErrRenderer(w http.ResponseWriter, baseTmpl *template.Template, msg string, reqs []string) error {
	tmpls := struct {
		Msg  string
		Reqs []string
	}{
		Msg:  msg,
		Reqs: reqs,
	}

	err := baseTmpl.ExecuteTemplate(w, "base", tmpls)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
