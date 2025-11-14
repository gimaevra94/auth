package consts

import "github.com/gimaevra94/auth/app/structs"

const (
	SignUpURL                    = "/sign-up"
	ServerAuthCodeSendURL        = "/server-auth-code-send"
	SignInURL                    = "/sign-in"
	GeneratePasswordResetLinkURL = "/generate-password-reset-link"
	HomeURL                      = "/home"
	Err500URL                    = "/500"
)

const RefreshTokenExp7Days = 7 * 24 * 60 * 60

const (
	successfulMailSendingStatus = "Mail sent successfully"
	failedMailSendingStatus     = "Failed to send mail"
	invalidLogin                = "Login is invalid"
	invalidEmail                = "Email is invalid"
	invalidPassword             = "Password is invalid"
	userAlreadyExist            = "User already exists"
	userNotExist                = "User does not exist"
	serverCodeMsg               = "Wrong code"
	userCodeMsg                 = "User code is empty"
	captchaRequiredMsg          = "Pass the verification reCAPTCHA."
	pleaseSignInByYandex        = "Please sign in by Yandex and set password"
	emptyCodeMsg                = "Code is empty"
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
	"successfulMailSendingStatus": {Msg: successfulMailSendingStatus, Regs: nil},
	"failedMailSendingStatus":     {Msg: failedMailSendingStatus, Regs: nil},
	"pleaseSignInByYandex":        {Msg: pleaseSignInByYandex, Regs: nil},
	"emptyCode":                   {Msg: emptyCodeMsg, Regs: nil},
}
