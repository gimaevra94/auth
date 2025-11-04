package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/gimaevra94/auth/app/consts"
)

var DB *sql.DB

func GetUniqueUserAgents(permanentUserId string) ([]string, error) {
	rows, err := DB.Query(consts.UserAgentSelectQuery, permanentUserId)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	var userAgents []string
	for rows.Next() {
		var userAgent string
		if err := rows.Scan(&userAgent); err != nil {
			return nil, errors.WithStack(err)
		}
		userAgents = append(userAgents, userAgent)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	return userAgents, nil
}

func DBConn() error {
	dbPassword := []byte(os.Getenv("DB_PASSWORD"))

	cfg := mysql.Config{
		User:   "root",
		Passwd: string(dbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
		DBName: "db",
	}

	var err error
	DB, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}

	err = DB.Ping()
	if err != nil {
		DB.Close()
		return errors.WithStack(err)
	}

	return nil
}

func DBClose() {
	if DB != nil {
		DB.Close()
	}
}

func GetSignUpUserFromDb(login string) error {
	row := DB.QueryRow(consts.SignUpUserSelectQuery, login)
	var DbEmail string

	err := row.Scan(&DbEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}

	return nil
}

func GetSignInUserFromDb(login, password string) (string, error) {
	row := DB.QueryRow(consts.SignInUserSelectQuery, login)
	var passwordHash sql.NullString
	var permanentUserId string

	err := row.Scan(&passwordHash, &permanentUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}

	if !passwordHash.Valid {
		return "", errors.New("password not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(password))
	if err != nil {
		return "", errors.WithStack(err)
	}

	return permanentUserId, nil
}

func GetRefreshTokenFromDb(permanentUserId, userAgent string) (string, string, bool, error) {
	row := DB.QueryRow(consts.RefreshTokenSelectQuery, permanentUserId, userAgent)
	var refreshToken string
	var deviceInfo string
	var refreshTokenCancelled bool

	err := row.Scan(&refreshToken, &deviceInfo, &refreshTokenCancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, errors.WithStack(err)
		}
		return "", "", false, errors.WithStack(err)
	}
	return refreshToken, deviceInfo, refreshTokenCancelled, nil
}

func GetYauthUserFromDb(login string) (string, error) {
	row := DB.QueryRow(consts.YauthSelectQuery, login)
	var permanentUserId string

	err := row.Scan(&permanentUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}

	return permanentUserId, nil
}

func GetMiddlewareUserFromDb(key string) (string, string, string, bool, error) {
	row := DB.QueryRow(consts.MWUserSelectQuery, key)
	var login string
	var email string
	var permanentUserId string
	var temporaryUserId bool
	err := row.Scan(&login, &email, &permanentUserId, &temporaryUserId)
	if err != nil {
		return "", "", "", false, errors.WithStack(err)
	}
	return login, email, permanentUserId, temporaryUserId, nil
}

func GetResetTokenCancelledFlagFromDb(signedToken string) (bool, error) {
	row := DB.QueryRow(consts.ResetTokenSelectQuery, signedToken)
	var cancelled bool
	err := row.Scan(&cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.New("reset token not found or invalId")
		}
		return false, errors.WithStack(err)
	}
	return cancelled, nil
}

func SetUserInDbTx(tx *sql.Tx, login, email, password, temporaryUserId, permanentUserId string, temporaryUserIdCancelled bool) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = tx.Exec(consts.UserInsertQuery, login, email, hashedPassword, temporaryUserId, permanentUserId, temporaryUserIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func SetTemporaryUserIdInDbByLoginTx(tx *sql.Tx, login, temporaryUserId string, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(consts.TemporaryIdUpdateQuery, temporaryUserId, temporaryUserIdCancelled, login)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryUserIdInDbByEmailTx(tx *sql.Tx, email, temporaryUserId string, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(consts.TemporaryIdUpdateByEmailQuery, temporaryUserId, temporaryUserIdCancelled, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenInDbTx(tx *sql.Tx, permanentUserId, refreshToken, deviceInfo string, refreshTokenCancelled bool) error {
	_, err := tx.Exec(consts.RefreshTokenInsertQuery, permanentUserId, refreshToken, deviceInfo, refreshTokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetYauthUserInDbTx(tx *sql.Tx, login, email, temporaryUserId, permanentUserId string, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(consts.YauthInsertQuery, login, email, temporaryUserId, permanentUserId, temporaryUserIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetResetTokenInDbTx(tx *sql.Tx, resetToken string) error {
	_, err := tx.Exec(consts.ResetTokenInsertQuery, resetToken, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func TokenCancelTx(tx *sql.Tx, refreshToken, deviceInfo string) error {
	_, err := tx.Exec(consts.RefreshtokenUpdateQuery, true, refreshToken, deviceInfo)
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func TemporaryUserIdCancelTx(tx *sql.Tx, temporaryUserId string) error {
	_, err := tx.Exec(consts.TemporaryUserIdUpdateQuery, true, temporaryUserId)
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func SetResetTokenCancelledFlagFromDbTx(tx *sql.Tx, tokenString string) error {
	_, err := tx.Exec(consts.ResetTokenUpdateQuery, tokenString)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordInDbByEmailTx(tx *sql.Tx, email, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = tx.Exec(consts.PasswordUpdateQuery, hashedPassword, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordInDbByTemporaryUserId(temporaryUserId, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = DB.Exec(consts.PasswordUpdateByPermanentIdQuery, hashedPassword, temporaryUserId)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func GetPermanentUserIdFromDb(email string) (string, error) {
	row := DB.QueryRow(consts.PermanentUserIdSelectQuery, email)
	var permanentUserId string
	err := row.Scan(&permanentUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return permanentUserId, nil
}

func GetPasswordFromDb(temporaryUserId string) (string, error) {
	row := DB.QueryRow(consts.PasswordSelectQuery, temporaryUserId)
	var passwordHash sql.NullString
	err := row.Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return passwordHash.String, nil
}
