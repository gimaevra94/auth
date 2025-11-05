package consts

import "github.com/gimaevra94/auth/app/structs"

const (
	SignUpURL        = "/sign-up"
	CodeSendURL      = "/code-send"
	SignInURL        = "/sign-in"
	PasswordResetURL = "/password-reset"
	HomeURL          = "/home"
	Err500URL        = "/500"
)

const RefreshTokenExp7Days = 7 * 24 * 60 * 60

const (
	SuccessfulMailSendingStatus = "Mail sent successfully"
	FailedMailSendingStatus     = "Failed to send mail"
	invalidLogin                = "Login is invalId"
	invalidEmail                = "Email is invalId"
	invalidPassword             = "Password is invalId"
	UserAlreadyExist            = "User already exists"
	UserNotExist                = "User does not exist"
	ServerCodeMsg               = "Wrong code"
	UserCodeMsg                 = "User code is empty"
	CaptchaRequiredMsg          = "Pass the verification reCAPTCHA."
	PasswordsDoNotMatch         = "Passwords do not match"
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
		"Domain must be valId and end with .com, .org, etc.",
	}
	PswrdReqs = []string{
		"8-30 characters long",
		"Latin letters only",
		"Numbers 0-9",
		"Special symbols: !@#$%^&*",
	}
)

var MessagesForUser = map[string]structs.MessagesForUser{
	"login":                       {Msg: invalidLogin, Regs: LoginReqs},
	"invalidEmail":                {Msg: invalidEmail, Regs: EmailReqs},
	"captchaRequired":             {Msg: CaptchaRequiredMsg, Regs: nil},
	"invalidPassword":             {Msg: invalidPassword, Regs: PswrdReqs},
	"passwordsDoNotMatch":         {Msg: PasswordsDoNotMatch, Regs: nil},
	"serverCode":                  {Msg: ServerCodeMsg, Regs: nil},
	"userCode":                    {Msg: UserCodeMsg, Regs: nil},
	"userAlreadyExist":            {Msg: UserAlreadyExist, Regs: nil},
	"userNotExist":                {Msg: UserNotExist, Regs: nil},
	"successfulMailSendingStatus": {Msg: SuccessfulMailSendingStatus, Regs: nil},
	"failedMailSendingStatus":     {Msg: FailedMailSendingStatus, Regs: nil},
}
