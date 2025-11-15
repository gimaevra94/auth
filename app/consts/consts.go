package consts

import "github.com/gimaevra94/auth/app/structs"

const (
	SignUpURL                    = "/sign-up"
	ServerAuthCodeSendURL        = "/server-auth-code-send"
	SignInURL                    = "/sign-in"
	GeneratePasswordResetLinkURL = "/generate-password-reset-link"
	HomeURL                      = "/home"
	Err500URL                    = "/500"
	ServerAuthCodeSendAgainURL   = "/server-auth-code-send-again"
)

const RefreshTokenExp7Days = 7 * 24 * 60 * 60

const (
	invalidLogin                   = "Login is invalid"
	invalidEmail                   = "Email is invalid"
	invalidPassword                = "Password is invalid"
	userAlreadyExist               = "User already exists"
	userNotExist                   = "User does not exist"
	captchaRequiredMsg             = "Pass the verification reCAPTCHA."
	pleaseSignInByYandexMsg        = "Please sign in by Yandex and set password"
	wrongCodeMsg                   = "Wrong code"
	failedMailSendingStatusMsg     = "Failed to send password reset link"
	successfulMailSendingStatusMsg = "Password reset link has been sent"
)

var (
	loginReqs = []string{
		"3-30 characters long",
		"Latin or Cyrillic letters",
		"Numbers 0-9",
	}
	emailReqs = []string{
		"Must contain Latin letters, numbers and allowed special characters: . _ % + -",
		"Must contain exactly one '@' symbol",
		"Domain must be valId and end with .com, .org, etc.",
	}
	PswrdReqs = []string{
		"8-30 characters long",
		"Latin letters only",
		"Numbers 0-9",
		"Special symbols: !@#$%^&*",
	}
)

var MsgForUser = map[string]structs.MsgForUser{
	"loginInvalid":                {Msg: invalidLogin, Regs: loginReqs},
	"emailInvalid":                {Msg: invalidEmail, Regs: emailReqs},
	"captchaRequired":             {Msg: captchaRequiredMsg, Regs: nil},
	"passwordInvalid":             {Msg: invalidPassword, Regs: PswrdReqs},
	"userAlreadyExist":            {Msg: userAlreadyExist, Regs: nil},
	"userNotExist":                {Msg: userNotExist, Regs: nil},
	"pleaseSignInByYandex":        {Msg: pleaseSignInByYandexMsg, Regs: nil},
	"wrongCode":                   {Msg: wrongCodeMsg, Regs: nil},
	"failedMailSendingStatus":     {Msg: failedMailSendingStatusMsg, Regs: nil},
	"successfulMailSendingStatus": {Msg: successfulMailSendingStatusMsg, Regs: nil},
}
