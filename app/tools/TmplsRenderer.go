package tools

import (
	"html/template"
	"net/http"

	"github.com/pkg/errors"
)

const (
	LoginMsg             = "Login is invalid"
	EmailMsg             = "Email is invalid"
	PasswrdMsg           = "Password is invalid"
	UserAlreadyExistMsg  = "User already exists"
	UserNotExistMsg      = "User does not exist"
	ServerCodeMsg        = "Wrong code"
	MailSendingStatusMsg = "Sending is secsessful"
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
	_        = Must(BaseTmpl.Parse(mailCodeTMPL))
)

type errMsg struct {
	Msg  string
	Regs []string
}

var ErrMsg = map[string]errMsg{
	"login":             {LoginMsg, LoginReqs},
	"email":             {EmailMsg, EmailReqs},
	"password":          {PasswrdMsg, PswrdReqs},
	"serverCode":        {ServerCodeMsg, nil},
	"alreadyExist":      {UserAlreadyExistMsg, nil},
	"notExist":          {UserNotExistMsg, nil},
	"mailSendingStatus": {MailSendingStatusMsg, nil},
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
	<link rel="stylesheet" href="/public/styles.css">
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
	<link rel="stylesheet" href="/public/styles.css">
</head>
<body>
	<div class="container">
		<h1>Sign Up</h1>
		{{if .Msg}}<div class="error-message">{{.Msg}}</div>{{end}}
		<form method="POST" action="/sign-up-input-check">
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
			<input type="hidden" id="recaptchaToken" name="g-recaptcha-response">
			<button type="submit" class="btn">Sign Up</button>
		</form>
		<div class="divider">
			<span>or</span>
		</div>
		<form method="POST" action="/yauth">
			<button type="submit" class="oauth-btn">Sign up with Yandex</button>
		</form>
		<div class="login-link">
			Already have an account? <a href="/sign-in">Sign In</a>
		</div>
	</div>
	<script src="https://www.google.com/recaptcha/api.js?render=6LcKXborAAAAAI3qmADWne38O4aAKjJIfPwMNBdO"></script>
	<script>
		grecaptcha.ready(function() {
			document.querySelector('form').addEventListener('submit', function(event) {
				event.preventDefault();
				grecaptcha.execute('6LcKXborAAAAAI3qmADWne38O4aAKjJIfPwMNBdO', {action: 'signup'}).then(function(token) {
					document.getElementById('recaptchaToken').value = token;
					event.target.submit();
				});
			});
		});
	</script>
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
	<link rel="stylesheet" href="/public/styles.css">
</head>
<body>
	<div class="container">
		<h1>Verification</h1>
		{{if .Msg}}<div class="error-message">{{.Msg}}</div>{{end}}
		<p class="message">We've sent a verification code to your email. Please enter it below.</p>
		<form method="POST" action="/user-add">
			<div class="form-group">
				<label for="clientCode">Verification Code</label>
				<input type="text" id="clientCode" name="clientCode" required maxlength="6" pattern="[0-9]*" inputmode="numeric">
			</div>
			<button type="submit" class="btn">Verify</button>
		</form>
		{{if .Msg}}
		<div class="resend">
			Didn't receive the code?
			<form method="GET" action="/code-send">
				<button type="submit" class="btn">Send again</button>
			</form>
		</div>
		{{end}}
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
	<link rel="stylesheet" href="/public/styles.css">
	<style>
		.error-highlight {
			color: #ff0000; /* Ярко-красный цвет */
			font-weight: bold;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>Sign In</h1>
		{{if .Msg}}
			{{if eq .Msg "User does not exist"}}
			<div class="error error-highlight">
				User does not exist
			</div>
			{{else}}
			<div class="error">{{.Msg}}</div>
			{{end}}
		{{end}}
		<form method="POST" action="/sign-in-input-check">
			<div class="form-group">
				<label for="login">Username</label>
				<input type="text" id="login" name="login" required autocomplete="username">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required autocomplete="current-password">
			</div>
			<!-- Google reCAPTCHA -->
			<input type="hidden" id="recaptchaTokenSignIn" name="g-recaptcha-response">
			<button type="submit" class="btn">Sign In</button>
		</form>
		<div class="divider">
			<span>or</span>
		</div>
		<form method="POST" action="/yauth">
			<button type="submit" class="oauth-btn">Sign in with Yandex</button>
		</form>
		{{if .ShowForgotPassword}}
		<div class="login-link">
			Forgot your password? <a href="/forgot-password-email">Reset Password</a>
		</div>
		{{end}}
		{{if eq .Msg "User does not exist"}}
		<div class="login-link">
			Don't have an account? <a href="/sign-up">Sign Up</a>
		</div>
		{{end}}
	</div>
	<script src="https://www.google.com/recaptcha/api.js?render=6LcKXborAAAAAI3qmADWne38O4aAKjJIfPwMNBdO"></script>
	<script>
		grecaptcha.ready(function() {
			document.querySelector('form[action="/sign-in-input-check"]').addEventListener('submit', function(event) {
				event.preventDefault();
				grecaptcha.execute('6LcKXborAAAAAI3qmADWne38O4aAKjJIfPwMNBdO', {action: 'signin'}).then(function(token) {
					document.getElementById('recaptchaTokenSignIn').value = token;
					event.target.submit();
				});
			});
		});
	</script>
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
	<link rel="stylesheet" href="/public/styles.css">
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Welcome</h1>
			<form method="GET" action="/logout">
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
	mailCodeTMPL = `
{{ define "mailCode" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Email Verification Code</title>
    <style>
        :root {
            --primary-color: #2563eb;
            --text-color: #e5e7eb;
            --bg-color: #1f2937;
            --container-bg: #374151;
            --border-color: #4b5563;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #1f2937; /* var(--bg-color); */
            color: #e5e7eb; /* var(--text-color); */
            line-height: 1.5;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh; /* Changed from height to min-height */
            margin: 0; /* Added */
            padding: 20px; /* Added */
        }
        .container {
            max-width: 400px;
            margin: 2rem auto; /* Added for centering */
            padding: 2rem;
            background: #374151; /* var(--container-bg); */
            border-radius: 8px;
            text-align: center;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #2563eb; /* var(--primary-color); */
        }
        .code-box {
            font-size: 2rem;
            letter-spacing: 0.3em;
            background: #2563eb; /* var(--primary-color); */
            color: #fff;
            padding: 0.5em 1em;
            border-radius: 6px;
            font-weight: bold;
            box-shadow: 0 2px 8px rgba(0,0,0,0.10);
            border: 0.5px solid #1d4ed8;
            display: inline-block;
            margin: 1.5rem 0;
        }
        p {
            margin-bottom: 1.5rem;
            color: #e5e7eb; /* var(--text-color); */
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Verification</h1>
        <p>Your verification code:</p>
        <div class="code-box">{{.Code}}</div>
        <p>Enter this code to continue.</p>
    </div>
</body>
</html>
{{ end }}
`
)
