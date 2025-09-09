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
	MsCodeMsg            = "Wrong code"
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
	_        = Must(BaseTmpl.Parse(PasswordResetTMPL))
	_        = Must(BaseTmpl.Parse(PasswordResetLinkTMPL))
	_        = Must(BaseTmpl.Parse(mailCodeTMPL))
	_        = Must(BaseTmpl.Parse(ForgotPasswordEmailTMPL))
)

type errMsg struct {
	Msg  string
	Regs []string
}

var ErrMsg = map[string]errMsg{
	"login":             {LoginMsg, LoginReqs},
	"email":             {EmailMsg, EmailReqs},
	"password":          {PasswrdMsg, PswrdReqs},
	"msCode":            {MsCodeMsg, nil},
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
			Already have an account? <a href="/sign_in">Sign In</a>
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
			Didn't receive the code? <a href="/user_add">Send again</a>
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
	<link rel="stylesheet" href="/public/styles.css">
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
			Forgot your password? <a href="/forgot_password_email">Reset Password</a>
		</div>
		{{end}}
	</div>
	<script src="https://www.google.com/recaptcha/api.js?render=6LcKXborAAAAAI3qmADWne38O4aAKjJIfPwMNBdO"></script>
	<script>
		grecaptcha.ready(function() {
			document.querySelector('form[action="/sign_in_input_check"]').addEventListener('submit', function(event) {
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

	PasswordResetLinkTMPL = `
{{ define "PasswordResetLink" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Request</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #1f2937; /* --bg-color */
            color: #e5e7eb; /* --text-color */
            line-height: 1.5;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh; /* Use min-height for emails */
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 400px;
            margin: 2rem auto; /* Added margin for better centering in email clients */
            padding: 2rem;
            background: #374151; /* --container-bg */
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            text-align: center;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #e5e7eb; /* --text-color */
        }
        p {
            margin-bottom: 1.5rem;
            color: #9ca3af;
        }
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background-color: #2563eb; /* --primary-color */
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none; /* Important for links */
            transition: background-color 0.2s;
        }
        .btn:hover {
            background-color: #1d4ed8; /* Darker primary for hover */
        }
        .footer {
            margin-top: 2rem;
            font-size: 0.8rem;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Password Reset Request</h1>
        <p>You recently requested to reset your password. Click the button below to reset it:</p>
        <a href="{{.ResetLink}}" class="btn">Reset Password</a>
        <p style="margin-top: 1.5rem;">If you did not request a password reset, please ignore this email.</p>
        <div class="footer">
            This email was sent from an automated system. Please do not reply.
        </div>
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
	<link rel="stylesheet" href="/public/styles.css">
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

const ForgotPasswordEmailTMPL = `
{{ define "ForgotPasswordEmail" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forgot Password</title>
    <link rel="stylesheet" href="/public/styles.css">
</head>
<body>
    <div class="container">
        <h1>Forgot Password</h1>
        {{if .Msg}}<div class="success message">{{.Msg}}</div>{{end}}
        <p class="message">Please enter your email address to receive a password reset link.</p>
        <form method="POST" action="/send_password_reset_link">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autocomplete="email">
            </div>
            <button type="submit" class="btn">Submit</button>
        </form>
        <div class="login-link">
            Remembered your password? <a href="/log_in">Sign In</a>
        </div>
    </div>
</body>
</html>
{{ end }}
`
