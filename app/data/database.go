package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/gimaevra94/auth/app/consts" 
)

var db *sql.DB

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
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return errors.WithStack(err)
	}

	return nil
}

func DBClose() {
	if db != nil {
		db.Close()
	}
}

func UserCheck(login, password string) (string, error) {
	row := db.QueryRow(consts.UserSelectQuery, login) 
	var passwordHash string
	var permanentUserID string
	err := row.Scan(&passwordHash, &permanentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(password))
	if err != nil {
		return "", errors.WithStack(err)
	}

	return permanentUserID, nil
}

func PasswordResetEmailCheck(email string) error {
	row := db.QueryRow(consts.PasswordResetEmailSelectQuery, email)
	var permanentUserID string
	err := row.Scan(&permanentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}
	return nil
}

func RefreshTokenCheck(permanentUserID, userAgent string) (string, string, bool, error) {
	row := db.QueryRow(consts.RefreshTokenSelectQuery, permanentUserID, userAgent)
	var refreshToken string
	var deviceInfo string
	var tokenCancelled bool

	err := row.Scan(&refreshToken, &deviceInfo, &tokenCancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, errors.WithStack(err)
		}
		return "", "", false, errors.WithStack(err)
	}
	return refreshToken, deviceInfo, tokenCancelled, nil
}

func YauthUserCheck(login string) (string, string, string, error) {
	row := db.QueryRow(consts.YauthSelectQuery, login) 
	var email string
	var password string
	var permanentUserID string
	err := row.Scan(&email, &password, &permanentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", "", errors.WithStack(err)
		}
		return "", "", "", errors.WithStack(err)
	}

	return email, password, permanentUserID, nil
}

func MWUserCheck(key string) (string, string, string, bool, error) {
	row := db.QueryRow(consts.MWUserSelectQuery, key) 
	var login string
	var email string
	var permanentUserID string
	var temporaryUserID bool
	err := row.Scan(&login, &email, &permanentUserID, &temporaryUserID)
	if err != nil {
		return "", "", "", false, errors.WithStack(err)
	}
	return login, email, permanentUserID, temporaryUserID, nil
}

func ResetTokenCheck(signedToken string) (bool, error) {
	row := db.QueryRow(consts.ResetTokenSelectQuery, signedToken)
	var cancelled bool
	err := row.Scan(&cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.New("reset token not found or invalid")
		}
		return false, errors.WithStack(err)
	}
	return cancelled, nil
}

func UserAdd(login, email, password, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = db.Exec(consts.UserInsertQuery, login, email, hashedPassword, temporaryUserID, permanentUserID, temporaryCancelled) 
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func TemporaryUserIDAdd(login, temporaryUserID string) error {
	_, err := db.Exec(consts.TemporaryIDUpdateQuery, temporaryUserID, login) 
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func RefreshTokenAdd(permanentUserID, refreshToken, deviceInfo string, tokenCancelled bool) error {
	_, err := db.Exec(consts.RefreshTokenInsertQuery, permanentUserID, refreshToken, deviceInfo, tokenCancelled) 
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func YauthUserAdd(login, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	_, err := db.Exec(consts.YauthInsertQuery, login, temporaryUserID, permanentUserID, temporaryCancelled) 
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func ResetTokenAdd(resetToken string) error {
	_, err := db.Exec(consts.ResetTokenInsertQuery, resetToken, false) 
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func TokenCancel(refreshToken, deviceInfo string) error {
	_, err := db.Exec(consts.RefreshtokenUpdateQuery, true, refreshToken, deviceInfo) 
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func TemporaryUserIDCancel(temporaryUserID string) error {
	_, err := db.Exec(consts.TemporaryUserIDUpdateQuery, true, temporaryUserID) 
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func ResetTokenCancel(tokenString string) error {
	_, err := db.Exec(consts.ResetTokenUpdateQuery, tokenString) 
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func UpdatePassword(email, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = db.Exec(consts.PasswordUpdateQuery, hashedPassword, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
