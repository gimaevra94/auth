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
	_        = Must(BaseTmpl.Parse(suspiciousLoginMailTMPL))
	_        = Must(BaseTmpl.Parse(PasswordResetTMPL))
	_        = Must(BaseTmpl.Parse(PasswordResetEmailTMPL))
	_        = Must(BaseTmpl.Parse(SetNewPasswordTMPL))
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
	"captchaRequired":   {"Пожалуйста, пройдите проверку reCAPTCHA.", nil},
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
		{{if .Regs}}
		<div class="requirements-list">
			{{range .Regs}}
			<div>{{.}}</div>
			{{end}}
		</div>
		{{end}}
		<form method="POST" action="/sign-up-input-check" id="signup-form">
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" id="username" name="login">
			</div>
			<div class="form-group">
				<label for="email">Email</label>
				<input type="email" id="email" name="email">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password">
			</div>
			<!-- Google reCAPTCHA -->
			{{if .CaptchaShow}}
			<div class="g-recaptcha g-recaptcha-centered" data-sitekey="6LfUPt4rAAAAAAEU_lnGN9DbW_QngiTObsj8ro0D"></div>
			{{end}}
			<button type="submit" class="btn" id="signup-button">Sign Up</button>
		</form>
		<div class="divider">
			<span>or</span>
		</div>
		<form method="GET" action="/yauth">
			<button type="submit" class="oauth-btn">Sign up with Yandex</button>
		</form>
		<div class="login-link">
			Already have an account? <a href="/sign-in">Sign In</a>
		</div>
	</div>
	<script>
		document.getElementById('signup-form').addEventListener('submit', function() {
			const button = document.getElementById('signup-button');
			button.disabled = true;
			button.textContent = 'Loading...';
		});
	</script>
	{{if .CaptchaShow}}
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	{{end}}
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
		{{if .Regs}}
		<div class="requirements-list">
			{{range .Regs}}
			<div>{{.}}</div>
			{{end}}
		</div>
		{{end}}
		<form method="POST" action="/sign-in-input-check">
			<div class="form-group">
				<label for="login">Username</label>
				<input type="text" id="login" name="login">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password">
			</div>
			<!-- Google reCAPTCHA -->
			{{if .CaptchaShow}}
			<div class="g-recaptcha" data-sitekey="6LfUPt4rAAAAAAEU_lnGN9DbW_QngiTObsj8ro0D"></div>
			{{end}}
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
	{{if .CaptchaShow}}
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	{{end}}
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
			<div class="header-buttons">
				<form method="GET" action="/logout">
					<button type="submit" class="btn btn-danger btn-equal-width">Sign Out</button>
				</form>
				<form method="GET" action="/simple-logout">
					<button type="submit" class="btn btn-primary btn-equal-width">Logout</button>
				</form>
			</div>
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
	<link rel="stylesheet" href="/public/styles.css">
</head>
<body>
	<div class="container">
		<h1>Password Reset</h1>
		{{if .Msg}}<div class="message">{{.Msg}}</div>{{end}}
		<p class="message">Enter your email to reset your password.</p>
		<form method="POST" action="/password-reset-email">
			<div class="form-group">
				<label for="email">Email</label>
				<input type="email" id="email" name="email" required autocomplete="email">
			</div>
			<button type="submit" class="btn">Submit</button>
		</form>
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

	suspiciousLoginMailTMPL = `
{{ define "suspiciousLoginMail" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Suspicious Login Attempt</title>
    <style>
        :root {
            --primary-color: #dc2626;
            --text-color: #e5e7eb;
            --bg-color: #1f2937;
            --container-bg: #374151;
            --border-color: #4b5563;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #1f2937;
            color: #e5e7eb;
            line-height: 1.5;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 400px;
            margin: 2rem auto;
            padding: 2rem;
            background: #374151;
            border-radius: 8px;
            text-align: center;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #dc2626; /* Red for warning */
        }
        p {
            margin-bottom: 1.5rem;
            color: #e5e7eb;
        }
        .warning-text {
            color: #fca5a5; /* Lighter red */
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Suspicious Login Attempt Detected!</h1>
        <p>Dear {{.Login}},</p>
        <p>We detected a login attempt to your account from an unrecognized device or location.</p>
        <p class="warning-text">Device Info: {{.DeviceInfo}}</p>
        <p>If this was you, you can ignore this email. If you did not attempt to log in, please secure your account immediately by changing your password.</p>
        <p>Thank you for your vigilance.</p>
    </div>
</body>
</html>
{{ end }}
`
	PasswordResetEmailTMPL = `
{{ define "PasswordResetEmail" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Password Reset</title>
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
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.5;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .container {
            max-width: 400px;
            padding: 2rem;
            background: var(--container-bg);
            border-radius: 8px;
            text-align: center;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: var(--primary-color);
        }
        p {
            margin-bottom: 1.5rem;
            color: var(--text-color);
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            margin-top: 1rem;
            background-color: var(--primary-color);
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Password Reset</h1>
        <p>You have requested a password reset. Please click the link below to reset your password:</p>
        <p><a href="{{.ResetLink}}" class="button">Reset Password</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
    </div>
</body>
</html>
{{ end }}
`
	SetNewPasswordTMPL = `
{{ define "SetNewPassword" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Set New Password</title>
    <link rel="stylesheet" href="/public/styles.css">
</head>
<body>
    <div class="container">
        <h1>Set New Password</h1>
        {{if .Msg}}<div class="error-message">{{.Msg}}</div>{{end}}
        <form method="POST" action="/set-new-password">
            <div class="form-group">
                <label for="oldPassword">Old Password</label>
                <input type="password" id="oldPassword" name="oldPassword" required autocomplete="current-password">
            </div>
            <div class="form-group">
                <label for="newPassword">New Password</label>
                <input type="password" id="newPassword" name="newPassword" required autocomplete="new-password">
            </div>
            <div class="form-group">
                <label for="confirmPassword">Confirm New Password</label>
                <input type="password" id="confirmPassword" name="confirmPassword" required autocomplete="new-password">
            </div>
            <button type="submit" class="btn">Set Password</button>
        </form>
    </div>
</body>
</html>
{{ end }}
`
)
