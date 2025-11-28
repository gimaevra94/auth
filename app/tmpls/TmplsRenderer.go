package tmpls

import (
	"html/template"
	"net/http"

	"github.com/pkg/errors"
)

func Must(t *template.Template, err error) *template.Template {
	return template.Must(t, err)
}

var (
	BaseTmpl = Must(template.New("base").Parse(baseTMPL))
	_        = Must(BaseTmpl.Parse(signUpTMPL))
	_        = Must(BaseTmpl.Parse(signInTMPL))
	_        = Must(BaseTmpl.Parse(homeTMPL))
	_        = Must(BaseTmpl.Parse(serverAuthCodeSendTMPL))
	_        = Must(BaseTmpl.Parse(emailMsgWithServerAuthCodeTMPL))
	_        = Must(BaseTmpl.Parse(emailMsgAboutSuspiciousLoginEmailTMPL))
	_        = Must(BaseTmpl.Parse(generatePasswordResetLinkTMPL))
	_        = Must(BaseTmpl.Parse(emailMsgWithPasswordResetLinkTMPL))
	_        = Must(BaseTmpl.Parse(setNewPasswordTMPL))
	_        = Must(BaseTmpl.Parse(emailMsgAboutNewDeviceLoginEmailTMPL))
)

var TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
	if err := tmpl.ExecuteTemplate(w, templateName, data); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

const (
	baseTMPL = `
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
	{{if .ShowCaptcha}}
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	{{end}}
</body>
</html>
{{ end }}
`
	signUpTMPL = `
{{ define "signUp" }}
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
		{{if .Msg}}<div class="error-msg">{{.Msg}}</div>{{end}}
		{{if .Regs}}
		<div class="requirements-list">
			{{range .Regs}}
			<div>{{.}}</div>
			{{end}}
		</div>
		{{end}}
		<form method="POST" action="/check-in-db-and-validate-sign-up-user-input" Id="signup-form">
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" Id="username" name="login">
			</div>
			<div class="form-group">
				<label for="email">Email</label>
				<input type="email" Id="email" name="email">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" Id="password" name="password">
			</div>
			<div class="form-group">
				<label>
					<input type="checkbox" name="rememberMe" value="true">
					Remember me
				</label>
			</div>
			{{if .ShowCaptcha}}
			<div class="g-recaptcha g-recaptcha-centered" data-sitekey="6LfUPt4rAAAAAAEU_lnGN9DbW_QngiTObsj8ro0D"></div>
			{{end}}
			<button type="submit" class="btn" Id="signup-button">Sign Up</button>
		</form>
		<div class="divIder signin-gap-fix">
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

	{{if .ShowCaptcha}}
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	{{end}}

</body>
</html>
{{ end }}
`

	serverAuthCodeSendTMPL = `
{{ define "serverAuthCodeSend" }}
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Verification Code</title>
    <link rel="stylesheet" href="/public/styles.css">
    <style>
        #clientCode {
            text-align: center;
            padding: 10px 0;
            font-size: 1.2em;
        }
        
        .resend-disabled {
            color: #888;
            pointer-events: none;
            text-decoration: none;
            cursor: not-allowed;
        }

        .captcha-container {
            margin: 15px 0;
            text-align: center;
            display: flex;
            justify-content: center;
        }
        
        .g-recaptcha {
            transform: scale(1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Verification</h1>
        {{if .Msg}}<div class="error-msg">{{.Msg}}</div>{{end}}
        <p class="msg">We've sent a verification code to your email. Please enter it below.</p>
        <form method="POST" action="/code-validate" id="codeForm">
            <div class="form-group-centered">
                <label for="clientCode">Verification Code</label>
                <input type="text" id="clientCode" name="clientCode" required maxlength="6" pattern="[0-9]*" inputmode="numeric">
            </div>
            {{if .ShowCaptcha}}
            <div class="captcha-container">
                <div class="g-recaptcha" data-sitekey="6LfUPt4rAAAAAAEU_lnGN9DbW_QngiTObsj8ro0D"></div>
            </div>
            {{end}}
            <button type="submit" class="btn">Verify</button>
        </form>
        <div class="login-link">
            Didn't receive the code? 
            <span id="resend-container">
                <a href="/server-auth-code-send-again" id="resend-link">Send again</a>
            </span>
            <span id="resend-timer" style="display: none;">
                Resend available in <span id="countdown">60</span>s
            </span>
        </div>
    </div>

    {{if .ShowCaptcha}}
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    {{end}}

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const resendLink = document.getElementById('resend-link');
            const resendContainer = document.getElementById('resend-container');
            const resendTimer = document.getElementById('resend-timer');
            const countdownElement = document.getElementById('countdown');
            
            const COOLDOWN_SECONDS = 60;
            const STORAGE_KEY = 'resendCooldownEnd';
            
            function checkCooldown() {
                const now = Math.floor(Date.now() / 1000);
                const cooldownEnd = localStorage.getItem(STORAGE_KEY);
                
                if (cooldownEnd && now < cooldownEnd) {
                    startCountdown(cooldownEnd - now);
                    return true;
                }
                return false;
            }
            
            function startCountdown(seconds) {
                let remaining = seconds;
                resendContainer.style.display = 'none';
                resendTimer.style.display = 'inline';
                
                const timer = setInterval(() => {
                    remaining--;
                    countdownElement.textContent = remaining;
                    
                    if (remaining <= 0) {
                        clearInterval(timer);
                        resendContainer.style.display = 'inline';
                        resendTimer.style.display = 'none';
                        localStorage.removeItem(STORAGE_KEY);
                    }
                }, 1000);
            }
            
            resendLink.addEventListener('click', function(e) {
                if (checkCooldown()) {
                    e.preventDefault();
                    return;
                }
                
                const cooldownEnd = Math.floor(Date.now() / 1000) + COOLDOWN_SECONDS;
                localStorage.setItem(STORAGE_KEY, cooldownEnd);
                
                startCountdown(COOLDOWN_SECONDS);
            });
            
            checkCooldown();
        });
    </script>
</body>
</html>
{{ end }}
`

	signInTMPL = `
{{ define "signIn" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Sign In</title>
	<link rel="stylesheet" href="/public/styles.css">
	<style>
		.error-highlight {
			color: #dc2626;
			font-weight: bold;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>Sign In</h1>
		{{if .Msg}}
			{{if eq .Msg "User does not exist"}}
			<div class="error-msg">User does not exist</div>
			{{else if eq .Msg "Pass the verification reCAPTCHA."}}
			<div class="error-msg">{{.Msg}}</div>
			{{else if eq .Msg "Please sign in by Yandex and set password"}}
			<div class="yandex-hint">{{.Msg}}</div>
			{{else if eq .Msg "Login is invalid"}}
			<div class="error-msg">{{.Msg}}</div>
			{{else if eq .Msg "Password is invalid"}}
			<div class="error-msg">{{.Msg}}</div>
			{{else}}
			<div class="error-msg">{{.Msg}}</div>
			{{end}}
		{{end}}
		{{if .Regs}}
		<div class="requirements-list">
			{{range .Regs}}
			<div>{{.}}</div>
			{{end}}
		</div>
		{{end}}
		<form method="POST" action="/check-in-db-and-validate-sign-in-user-input">
			<div class="form-group">
				<label for="login">Username</label>
				<input type="text" Id="login" name="login">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" Id="password" name="password">
			</div>
             <div class="form-group">
 <label>
 <input type="checkbox" name="rememberMe" value="true">
 Remember me
 </label>
 </div>
			{{if .ShowCaptcha}}
			<div class="g-recaptcha g-recaptcha-centered" data-sitekey="6LfUPt4rAAAAAAEU_lnGN9DbW_QngiTObsj8ro0D"></div>
			{{end}}
			<button type="submit" class="btn">Sign In</button>
		</form>
		<div class="divIder">
			<span>or</span>
		</div>
		<form method="GET" action="/yauth">
			<button type="submit" class="oauth-btn">Sign in with Yandex</button>
		</form>
		{{if .ShowForgotPassword}}
		<div class="error-msg reset-hint">
			Forgot your password? <a href="/generate-password-reset-link">Reset Password</a>
		</div>
		{{end}}
		<div class="login-link signin-gap-fix">
			Don't have an account? <a href="/sign-up">Sign Up</a>
		</div>
	</div>
	{{if .ShowCaptcha}}
	<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	{{end}}
</body>
</html>
{{ end }}
`

	homeTMPL = `
{{ define "home" }}
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
					<button type="submit" class="btn btn-danger">Sign Out</button>
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
	generatePasswordResetLinkTMPL = `
{{ define "generatePasswordResetLink" }}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Password Reset</title>
	<link rel="stylesheet" href="/public/styles.css">
</head>
<body>
	<div class="container">
		{{if not .Msg}}
		<h1>Password Reset</h1>
		<p class="msg">Enter your email to reset your password.</p>
		<form method="POST" action="/generate-password-reset-link">
			<div class="form-group">
				<label for="email">Email</label>
				<input type="email" Id="email" name="email" required autocomplete="email">
			</div>
			<button type="submit" class="btn">Submit</button>
		</form>
		{{else}}
			{{if eq .Msg "Password reset link has been sent."}}
				<div class="msg success-msg" style="text-align:center; padding: 1.5rem 0;">{{.Msg}}</div>
			{{else if eq .Msg "Password reset link has been sent to your email."}}
				<div class="msg success-msg" style="text-align:center; padding: 1.5rem 0;">{{.Msg}}</div>
			{{else if eq .Msg "Password reset link has been sent"}}
				<div class="msg success-msg" style="text-align:center; padding: 1.5rem 0;">{{.Msg}}</div>
			{{else}}
				<div class="error-msg" style="text-align:center; padding: 1.5rem 0;">{{.Msg}}</div>
				<a href="/sign-up" class="btn" style="margin-top: 1rem;">Go to Sign-up Page</a>
			{{end}}
		{{end}}
	</div>
</body>
</html>
{{ end }}
`
	emailMsgWithServerAuthCodeTMPL = `
{{ define "emailMsgWithServerAuthCode" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="wIdth=device-wIdth, initial-scale=1">
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
            max-wIdth: 400px;
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
            border: 0.5px solId #1d4ed8;
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
	emailMsgAboutSuspiciousLoginEmailTMPL = `
{{ define "emailMsgAboutSuspiciousLoginEmail" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="wIdth=device-wIdth, initial-scale=1">
    <title>Suspicious login attempt</title>
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
            max-wIdth: 400px;
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
    <h1>Suspicious login attempt detected</h1>
    <p>Login attempt from: {{.UserAgent}}.</p>
    <p>If unauthorized, change your password immediately.</p>
</div>
</body>
</html>
{{ end }}
`
	emailMsgWithPasswordResetLinkTMPL = `
{{ define "emailMsgWithPasswordResetLink" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="wIdth=device-wIdth, initial-scale=1">
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
            max-wIdth: 400px;
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
        <p>You have requested a password reset. Please click the button below to reset your password:</p>
        <p>
            <a href="{{.ResetLink}}" target="_blank" rel="noopener" role="button" style="
                display:inline-block;
                background-color:#2563eb;
                color:#ffffff;
                text-decoration:none;
                padding:10px 20px;
                border-radius:6px;
                font-weight:600;">
                Reset Password
            </a>
        </p>
        <p>If you don't see the button or it doesn't work, you can simply click this link, or copy and paste it into your browser:</p>
        <p>{{.ResetLink}}</p>
        <p>If you dId not request a password reset, please ignore this email.</p>
    </div>
</body>
</html>
{{ end }}
`
	setNewPasswordTMPL = `
{{ define "setNewPassword" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="wIdth=device-wIdth, initial-scale=1">
    <title>Set New Password</title>
    <link rel="stylesheet" href="/public/styles.css">
</head>
<body>
    <div class="container">
        <h1>Set New Password</h1>
        {{if .Msg}}<div class="error-msg">{{.Msg}}</div>{{end}}
        <form method="POST" action="/set-new-password">
            <div class="form-group">
                <label for="oldPassword">Old Password</label>
                <input type="password" Id="oldPassword" name="oldPassword" required autocomplete="current-password">
            </div>
            <div class="form-group">
                <label for="newPassword">New Password</label>
                <input type="password" Id="newPassword" name="newPassword" required autocomplete="new-password">
            </div>
            <div class="form-group">
                <label for="confirmPassword">Confirm New Password</label>
                <input type="password" Id="confirmPassword" name="confirmPassword" required autocomplete="new-password">
            </div>
            <input type="hIdden" name="token" value="{{.Token}}">
            <button type="submit" class="btn">Set Password</button>
        </form>
    </div>
</body>
</html>
{{ end }}
`
	emailMsgAboutNewDeviceLoginEmailTMPL = `
{{ define "emailMsgAboutNewDeviceLoginEmail" }}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="wIdth=device-wIdth, initial-scale=1">
    <title>New device login</title>
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
            max-wIdth: 400px;
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
        p {
            margin-bottom: 1.5rem;
            color: #e5e7eb; /* var(--text-color); */
        }
    </style>
</head>
<body>
<div class="container">
    <h1>New device login</h1>
    <p>Detected a login from a new device</p>
    <p>If this was not you, change your password</p>
</div>
</body>
</html>
{{ end }}
`
)
