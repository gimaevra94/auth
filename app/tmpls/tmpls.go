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
