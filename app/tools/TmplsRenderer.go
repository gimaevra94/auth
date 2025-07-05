package tools

import (
	"html/template"
	"net/http"

	"github.com/gimaevra94/auth/app/consts/constsTmpls"
	"github.com/pkg/errors"
)

func Must(t *template.Template, err error) *template.Template {
	return template.Must(t, err)
}

var (
	BaseTmpl = Must(template.New("base").Parse(constsTmpls.BaseTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.SignUpTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.SignInTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.HomeTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.BadSignUpTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.BadSignInTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.CodeSendTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.LogoutTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.InternalServerErrorTMPL))
	_        = Must(BaseTmpl.Parse(constsTmpls.MailCodeTMPL))
)

var (
	LoginReqs = []string{
		"3-30 characters long",
		"Latin or Cyrillic letters",
		"Numbers 0-9",
	}
	EmailReqs = []string{
		"Must contain Latin letters, numbers and allowed special characters: . _ % + -",
		"Must contain exactly one '@' symbol",
		"Domain must be valid and end with .com, .org, etc.",
	}
	PswrdReqs = []string{
		"8-30 characters long",
		"Latin letters only",
		"Numbers 0-9",
		"Special symbols: !@#$%^&*",
	}

	LoginMsg            = "Login invalid"
	EmailMsg            = "Email invalid"
	PasswrdMsg          = "Password invalid"
	UserAlreadyExistMsg = "User already exist"
	MsCodeMsg           = "Wrong code"
)

type errMsg struct {
	Msg  string
	Regs []string
}

var ErrMsg = map[string]errMsg{
	"login":        {LoginMsg, LoginReqs},
	"email":        {EmailMsg, EmailReqs},
	"password":     {PasswrdMsg, PswrdReqs},
	"msCode":       {MsCodeMsg, nil},
	"alreadyExist": {UserAlreadyExistMsg, nil},
}

func TmplsRenderer(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
	err := tmpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
