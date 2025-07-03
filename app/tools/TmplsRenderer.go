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
	_        = Must(BaseTmpl.Parse(tmpls.SignInTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.HomeTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.BadSignUpTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.BadSignInTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.CodeSendTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.LogoutTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.InternalServerErrorTMPL))
	_        = Must(BaseTmpl.Parse(tmpls.MailCodeTMPL))
)

func TmplsRenderer(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
	err := tmpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
