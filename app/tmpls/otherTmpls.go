package tmpls

const BaseTMPL = `
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

const SignUpTMPL = `
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
{{ end }}
<!-- Подключение скрипта Google reCAPTCHA -->
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
`

const InternalServerErrorTMPL = `
{{ define "title" }}Internal Server Error{{ end }}

{{ define "content" }}
<div class="container">
    <h1>Internal Server Error</h1>
    <p>We're sorry, something went wrong on our end. Please try again later.</p>
    <a href="/" class="btn">Go to Home Page</a>
</div>
{{ end }}
`

const BadSignUpTMPL = `
{{ define "title" }}Invalid Sign Up{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
    <h1>Invalid Sign Up</h1>
    <p class="message">Please check the following requirements for your username, password and email:</p>
    <div class="requirements">
        <h2>Email Requirements:</h2>
        <ul>
            <li>• Must contain only Latin letters (a-z, A-Z), numbers (0-9), and allowed special characters: . _ % + -</li>
            <li>• Must contain exactly one "@" symbol</li>
            <li>• Must have a valid domain name after "@" (letters, numbers, hyphens, dots)</li>
            <li>• Domain must end with a dot and at least two Latin letters (e.g., .com, .ru, .org)</li>
            <li>• No spaces or invalid characters allowed</li>
        </ul>
    </div>
    <div class="requirements">
        <h2>Username Requirements:</h2>
        <ul>
            <li>• 3-30 characters long</li>
            <li>• Latin or Cyrillic letters</li>
            <li>• Numbers 0-9</li>
        </ul>
    </div>
    <div class="requirements">
        <h2>Password Requirements:</h2>
        <ul>
            <li>• 8-30 characters long</li>
            <li>• Latin letters only</li>
            <li>• Numbers 0-9</li>
            <li>• Special symbols: !@#$%^&*</li>
        </ul>
    </div>
    <div>
        <a href="/sign_up" class="btn">Try Again</a>
        <a href="/log_in" class="btn btn-secondary">Sign In</a>
    </div>
</div>
{{ end }}
`

const BadSignInTMPL = `
{{ define "title" }}Invalid Sign In{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
    <h1>Invalid Sign In</h1>
    <p class="message">The username or password you entered is incorrect. Please try again or sign up for a new account.</p>
    <div>
        <a href="/sign_in" class="btn">Try Again</a>
        <a href="/sign_up" class="btn btn-secondary">Sign Up</a>
    </div>
</div>
{{ end }}
`

const CodeSendTMPL = `
{{ define "title" }}Verification Code{{ end }}

{{ define "content" }}
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
{{ end }}
`

const HomeTMPL = `
{{ define "title" }}Home{{ end }}

{{ define "content" }}
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
{{ end }}
`

const LogoutTMPL = `
{{ define "title" }}Signed Out{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="success-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
        <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
    <h1>Successfully Signed Out</h1>
    <p class="message">You have been successfully signed out of your account. Thank you for using our service.</p>
    <a href="/log_in" class="btn">Sign In Again</a>
</div>
{{ end }}
`

const MailCodeTMPL = `
{{ define "title" }}Access Code{{ end }}

{{ define "content" }}
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
    <div style="color:#9ca3af;text-align:center;font-size:0.95rem;">
        If you did not request this code, please ignore this email.
    </div>
</div>
{{ end }}
`

const PageNotFoundTMPL = `
{{ define "title" }}404 — Page Not Found{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="8" y1="12" x2="16" y2="12" />
    </svg>
    <h1>404 — Page Not Found</h1>
    <p class="message">Sorry, the page you are looking for does not exist or has been removed.<br>Please check the URL or go back to the previous page.</p>
    <div>
        <a href="javascript:history.back()" class="btn">Back</a>
    </div>
</div>
{{ end }}
`

const RequestErrorTMPL = `
{{ define "title" }}Request Error{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
    <h1>Request Error</h1>
    <p class="message">An error occurred while processing your request. Please try again later or contact support.</p>
    <div>
        <a href="javascript:history.back()" class="btn btn-secondary">Back</a>
    </div>
</div>
{{ end }}
`

const UserAlreadyExistTMPL = `
{{ define "title" }}User Already Exists{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
    <h1>User Already Exists</h1>
    <p class="message">A user with this email is already registered. Please sign in or use a different email address.</p>
    <a href="/sign_in" class="btn">Sign In</a>
</div>
{{ end }}
`

const UserNotExistTMPL = `
{{ define "title" }}User Not Found{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
    <h1>User Not Found</h1>
    <p class="message">No user found with the provided credentials. Please check your input or sign up for a new account.</p>
    <div>
        <a href="/log_in" class="btn">Try Again</a>
        <a href="/sign_up" class="btn btn-secondary">Sign Up</a>
    </div>
</div>
{{ end }}
`

const WrongCodeTMPL = `
{{ define "title" }}Invalid Code{{ end }}

{{ define "content" }}
<div class="container">
    <svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
    <h1>Invalid Code</h1>
    <p class="message">The verification code you entered is incorrect. Please check the code and try again.</p>
    <a href="/code_send" class="btn">Try Again</a>
</div>
{{ end }}
`

const SignInTMPL = `
{{ define "title" }}Sign In{{ end }}

{{ define "content" }}
<h1>Sign In</h1>
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
{{ end }}
<!-- Подключение скрипта Google reCAPTCHA -->
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
`
