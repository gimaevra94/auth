package tools

import (
	"html/template"
	"net/http"

	"github.com/pkg/errors"
)

const (
	LoginMsg            = "Login invalid"
	EmailMsg            = "Email invalid"
	PasswrdMsg          = "Password invalid"
	UserAlreadyExistMsg = "User already exist"
	UserNotExistMsg     = "User not exist"
	MsCodeMsg           = "Wrong code"
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
)

func Must(t *template.Template, err error) *template.Template {
	return template.Must(t, err)
}

var (
	BaseTmpl = Must(template.New("base").Parse(BaseTMPL))
	_        = Must(BaseTmpl.Parse(SignUpTMPL))
	_        = Must(BaseTmpl.Parse(SignInTMPL))
	_        = Must(BaseTmpl.Parse(HomeTMPL))
	_        = Must(BaseTmpl.Parse(CodeSendTMPL))
	_        = Must(BaseTmpl.Parse(PasswordResetTMPL))
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
	"notExist":     {UserNotExistMsg, nil},
}

func TmplsRenderer(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
	err := tmpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

const (
	BaseTMPL = `
{{ define "base" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>{{ block "title" . }}Default Title{{ end }}</title>
	<link rel="stylesheet" href="C:/Users/gimaevra94/Documents/git/auth/styles.css">
</head>
<body>
	<div class="container">
		{{ template "content" . }}
	</div>
</body>
</html>
{{ end }}
`

	SignUpTMPL = `
{{ define "SignUp" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Sign Up</title>
	<link rel="stylesheet" href="C:/Users/gimaevra94/Documents/git/auth/styles.css">
</head>
<body>
	<div class="container">
		<h1>Sign Up</h1>
		{{if .Msg}}<div class="error">{{.Msg}}</div>{{end}}
		<form method="POST" action="/sign_up_input_check">
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
			<!-- Google reCAPTCHA -->
			<div class="g-recaptcha" data-sitekey="6LeTKHUrAAAAAAoKY_j2RF_ZZtCYgjyr8yv1c7dE"></div>
			<button type="submit" class="btn">Sign Up</button>
		</form>
		<div class="divider">
			<span>or</span>
		</div>
		<form method="POST" action="/yauth">
			<button type="submit" class="oauth-btn">Sign up with Yandex</button>
		</form>
		<div class="login-link">
			Already have an account? <a href="/sign_in">Sign In</a>
		</div>
		<div class="login-link">
			Forgot your password? <a href="/password_reset">Reset Password</a>
		</div>
	</div>
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
</body>
</html>
{{ end }}
`

	CodeSendTMPL = `
{{ define "CodeSend" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Verification Code</title>
	<link rel="stylesheet" href="C:/Users/gimaevra94/Documents/git/auth/styles.css">
</head>
<body>
	<div class="container">
		<h1>Verification</h1>
		<p class="message">We've sent a verification code to your email. Please enter it below.</p>
		<form method="POST" action="/user_add">
			<input type="hidden" name="rememberMe" value="false">
			<div class="form-group">
				<label for="userCode">Verification Code</label>
				<input type="text" id="userCode" name="userCode" required maxlength="6" pattern="[0-9]*" inputmode="numeric">
			</div>
			<button type="submit" class="btn">Verify</button>
		</form>
		<div class="resend">
			Didn't receive the code? <a href="/code_send">Send again</a>
		</div>
	</div>
</body>
</html>
{{ end }}
`

	SignInTMPL = `
{{ define "SignIn" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Sign In</title>
	<link rel="stylesheet" href="C:/Users/gimaevra94/Documents/git/auth/styles.css">
</head>
<body>
	<div class="container">
		<h1>Sign In</h1>
		{{if .Msg}}<div class="error">{{.Msg}}</div>{{end}}
		<form method="POST" action="/sign_in_input_check">
			<div class="form-group">
				<label for="login">Username</label>
				<input type="text" id="login" name="login" required autocomplete="username">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required autocomplete="current-password">
			</div>
			<div class="form-group" style="margin-top:1em;">
				<input type="hidden" name="rememberMe" value="false">
				<label style="display:flex;align-items:center;gap:0.5em;">
					<input type="checkbox" name="rememberMe" value="true">
					Remember me
				</label>
			</div>
			<!-- Google reCAPTCHA -->
			<div class="g-recaptcha" data-sitekey="6LeTKHUrAAAAAAoKY_j2RF_ZZtCYgjyr8yv1c7dE"></div>
			<button type="submit" class="btn">Sign In</button>
		</form>
		<div class="divider">
			<span>or</span>
		</div>
		<form method="POST" action="/yauth">
			<button type="submit" class="oauth-btn">Sign in with Yandex</button>
		</form>
		<div class="login-link">
			Forgot your password? <a href="/password_reset">Reset Password</a>
		</div>
	</div>
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
</body>
</html>
{{ end }}
`

	HomeTMPL = `
{{ define "Home" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Home</title>
	<link rel="stylesheet" href="C:/Users/gimaevra94/Documents/git/auth/styles.css">
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Welcome</h1>
			<form method="POST" action="/logout">
				<button type="submit" class="btn btn-danger">Sign Out</button>
			</form>
		</div>
		<div class="welcome">
			<p>You have successfully signed in. You can now use all the features of the application.</p>
		</div>
	</div>
</body>
</html>
{{ end }}
`

	PasswordResetTMPL = `
{{ define "PasswordReset" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <link rel="stylesheet" href="baseTmpl.css">
</head>
<body>
    <div class="container">
        <h1>Password Reset</h1>
        <form method="POST" action="/password_reset">
            <div class="form-group">
                <label for="oldPassword">Old Password</label>
                <input type="password" id="oldPassword" name="oldPassword" required autocomplete="current-password">
            </div>
            <div class="form-group">
                <label for="oldPasswordConfirm">Confirm Old Password</label>
                <input type="password" id="oldPasswordConfirm" name="oldPasswordConfirm" required autocomplete="current-password">
            </div>
            <div class="form-group">
                <label for="newPassword">New Password</label>
                <input type="password" id="newPassword" name="newPassword" required autocomplete="new-password">
            </div>
            <button type="submit" class="btn">Submit</button>
        </form>
    </div>
</body>
</html>
{{ end }}
`

	Err500TMPL = `
{{ define "Err500" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Internal Server Error</title>
	<link rel="stylesheet" href="C:/Users/gimaevra94/Documents/git/auth/styles.css">
</head>
<body>
	<div class="container">
		<h1>Internal Server Error</h1>
		<p>We're sorry, something went wrong on our end. Please try again later.</p>
		<a href="/home" class="btn">Go to Home Page</a>
	</div>
</body>
</html>
{{ end }}
`
)
