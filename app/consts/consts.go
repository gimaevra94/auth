package consts

const (
	CodeSendURL     = "/code_send"
	SignInURL       = "/sign_in"
	HomeURL         = "/home"
	UserAddURL      = "/user_add"
	LogoutURL       = "/logout"
	BadSignInURL    = "/bad_sign_in"
	BadSignUpURL    = "/bad_sign_up"
	BadEmailURL     = "/bad_email"
	UserNotExistURL = "/user_not_exist"
	WrongCodeURL    = "/wrong_code"
	AlreadyExistURL = "/already_exist"
	Err500URL       = "/500"
	InputCheckURL   = "/input_check"

	NotExistErr = "not exist"
	InvalidErr  = "invalid"

	NoExpiration = 253402300799.0
)

const (
	BaseTMPL = `
	{{ define "base" }}
	<!DOCTYPE html>
	<html lang="ru">
	<head>
		<meta charset="UTF-8">
		<title>{{ block "title" . }}Default Title{{ end }}</title>
		<link rel="stylesheet" href="baseTmpl.css">
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
		<link rel="stylesheet" href="baseTmpl.css">
	</head>
	<body>
		<div class="container">
			<h1>Sign Up</h1>
			{{if .Msg}}<div class="error">{{.Msg}}</div>{{end}}
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
				Already have an account? <a href="/log_in">Sign In</a>
			</div>
		</div>
		<script src="https://www.google.com/recaptcha/api.js" async defer></script>
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
		<link rel="stylesheet" href="baseTmpl.css">
	</head>
	<body>
		<div class="container">
			<h1>Internal Server Error</h1>
			<p>We're sorry, something went wrong on our end. Please try again later.</p>
			<a href="/" class="btn">Go to Home Page</a>
		</div>
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
		<link rel="stylesheet" href="baseTmpl.css">
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

	HomeTMPL = `
	{{ define "Home" }}
	<!DOCTYPE html>
	<html lang="ru">
	<head>
		<meta charset="UTF-8">
		<title>Home</title>
		<link rel="stylesheet" href="baseTmpl.css">
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
	LogoutTMPL = `
	{{ define "Logout" }}
	<!DOCTYPE html>
	<html lang="ru">
	<head>
		<meta charset="UTF-8">
		<title>Signed Out</title>
		<link rel="stylesheet" href="baseTmpl.css">
	</head>
	<body>
		<div class="container">
			<svg class="success-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
				<polyline points="22 4 12 14.01 9 11.01" />
			</svg>
			<h1>Successfully Signed Out</h1>
			<p class="message">You have been successfully signed out of your account. Thank you for using our service.</p>
			<a href="/log_in" class="btn">Sign In Again</a>
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
		<link rel="stylesheet" href="baseTmpl.css">
	</head>
	<body>
		<div class="container">
			<h1>Sign In</h1>
			{{if .Msg}}<div class="error">{{.Msg}}</div>{{end}}
			<form method="POST" action="/log_in">
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
		</div>
		<script src="https://www.google.com/recaptcha/api.js" async defer></script>
	</body>
	</html>
	{{ end }}
	`
)

/*MailCodeTMPL = `
{{ define "MailCode" }}
<!DOCTYPE html>
<html lang="ru">
<head>
	<meta charset="UTF-8">
	<title>Access Code</title>
	<link rel="stylesheet" href="baseTmpl.css">
</head>
<body>
	<div class="container">
		<h1>Your access code:</h1>
		<div style="text-align:center;margin:1.5rem 0;">
			<span style="display:inline-block;font-size:2rem;letter-spacing:0.3em;background:#2563eb;color:#fff;padding:0.5em 1em;border-radius:6px;font-weight:bold;box-shadow:0 2px 8px rgba(0,0,0,0.10);border:0.5px solid #1d4ed8;">
				{{.Code}}
			</span>
		</div>
		<div style="color:#9ca3af;text-align:center;font-size:0.95rem;margin-bottom:1.5rem;">
			Enter this code to continue.
		</div>
	</div>
</body>
</html>
{{ end }}
`*/
