package tmpls

import (
	"html/template"
	"net/http"

	"github.com/pkg/errors"
)

var (
	BaseTmpl = Must(template.New("base").Parse(base))
	_        = Must(BaseTmpl.Parse(signUp))

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

	LoginMsg = "Login invalid"
	EmailMsg = "Email invalid"
	PasswrdMsg    = "Password invalid"
	LoginTimerMsg = "exceeded the number of login attempts, try later"
)

func ErrRenderer(w http.ResponseWriter, baseTmpl *template.Template, msg string, reqs []string) error {
	data := struct {
		Msg  string
		Reqs []string
	}{
		Msg:  msg,
		Reqs: reqs,
	}

	err := baseTmpl.ExecuteTemplate(w, signUp, data)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func Must(t *template.Template, err error) *template.Template {
	return template.Must(t, err)
}

const base = `
{{ define "base" }}
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>{{ block "title" . }}Default Title{{ end }}</title>
    <link rel="stylesheet" href="/static/css/signup.css">
</head>
<body>
    <div class="container">
        {{ template "content" . }}
    </div>
</body>
</html>
{{ end }}
`

const signUp = `
{{ define "title" }}Sign Up{{ end }}

{{ define "content" }}
<h1>Sign Up</h1>
<form method="POST" action="/input_check">
    <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="login" required autocomplete="username">
    </div>
    <div class="form-group">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required autocomplete="email">
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autocomplete="new-password">
    </div>
    <button type="submit" class="btn">Sign Up</button>
</form>
<div class="divider">
    <span>or</span>
</div>
<form method="POST" action="/yauth">
    <button type="submit" class="oauth-btn">Sign up with Yandex</button>
</form>
<div class="login-link">
    Already have an account? <a href="/log_in">Sign In</a>
</div>
{{ end }}
`
