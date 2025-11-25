package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	permanentIdAndPasswordHashSelectQuery = "select permanentId, passwordHash from password_hash where login = ? and cancelled = false"
	refreshTokenSelectQuery               = "select token, cancelled from refresh_token where permanentId = ? and userAgent = ?"

	uniqueUserAgentsSelectQuery            = "select userAgent from temporary_id where permanentId = ?"
	permanentIdByEmailSelectQuery          = "select permanentId from email where email = ? and yauth = ? and cancelled = false"
	temporaryIdCancelledSelectQuery        = "select cancelled from temporary_id where temporaryId = ? and cancelled = false"
	temporaryIdNotCancelledSelectQuery     = "select permanentId from temporary_id where temporaryId = ? and cancelled = false"
	resetTokenCancelledSelectQuery         = "select cancelled from reset_token where token = ? and cancelled = false"
	emailSelectQuery                       = "select email,yauth from email where permanentId = ? and cancelled = false"
	temporaryIdSelectQuery                 = "select permanentId, userAgent from temporary_id where temporaryId = ?"
	permanentIdByTemporaryIdSelectQuery    = "select permanentId from temporary_id where temporaryId = ?"
	passwordResetTokenCancelledSelectQuery = "select cancelled from password_reset_token where token = ? and cancelled = false"

	loginInsertQuery              = "insert into login (permanentId, login, cancelled) values (?, ?, ?)"
	emailInsertQuery              = "insert into email (permanentId, email,yauth,cancelled) values (?, ?, ?, ?)"
	passwordHashInsertQuery       = "insert into password_hash (permanentId, passwordHash, cancelled) values (?, ?, ?)"
	temporaryIdInsertQuery        = "insert into temporary_id (permanentId, temporaryId, userAgent,cancelled) values (?, ?, ?, ?)"
	refreshTokenInsertQuery       = "insert into refresh_token (permanentId, token, userAgent,cancelled) values (?, ?, ?, ?)"
	passwordResetTokenInsertQuery = "insert into password_reset_token (token, cancelled) values (?, ?)"

	loginUpdateQuery        = "update login set cancelled = true where permanentId = ? and cancelled = false"
	emailUpdateQuery        = "update email set cancelled = true where permanentId = ? and yauth = ? and cancelled = false"
	passwordHashUpdateQuery = "update password_hash set cancelled = true where permanentId = ? and cancelled = false"
	temporaryIdUpdateQuery  = "update temporary_id set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	refreshTokenUpdateQuery = "update refresh_token set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
)

var Db *sql.DB

func DbConn() error {
	DbPassword := []byte(os.Getenv("DB_PASSWORD"))
	cfg := mysql.Config{
		User:   "root",
		Passwd: string(DbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
		DBName: "db",
	}
	var err error

	Db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}
	if err = Db.Ping(); err != nil {
		Db.Close()
		return errors.WithStack(err)
	}
	return nil
}

func DbClose() {
	if Db != nil {
		Db.Close()
	}
}

func GetPermanentIdFromDbByEmail(email string, yauth bool) (string, error) {
	var permanentId string
	row := Db.QueryRow(permanentIdByEmailSelectQuery, email, yauth)
	err := row.Scan(&permanentId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}

func GetUniqueUserAgentsFromDb(permanentId string) ([]string, error) {
	rows, err := Db.Query(uniqueUserAgentsSelectQuery, permanentId)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	var uniqueUserAgents []string
	for rows.Next() {
		var userAgent string
		if err := rows.Scan(&userAgent); err != nil {
			return nil, errors.WithStack(err)
		}
		uniqueUserAgents = append(uniqueUserAgents, userAgent)
	}
	return uniqueUserAgents, nil
}

func GetTemporaryIdKeysFromDb(temporaryId string) (string, string, error) {
	row := Db.QueryRow(temporaryIdSelectQuery, temporaryId)
	var permanentId, userAgent string
	err := row.Scan(&permanentId, &userAgent)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	return permanentId, userAgent, nil
}

func GetEmailFromDb(permamentId string) (string, bool, error) {
	row := Db.QueryRow(emailSelectQuery, permamentId)
	var email string
	var yauth bool
	err := row.Scan(&email, &yauth)
	if err != nil {
		return "", false, errors.WithStack(err)
	}
	return email, yauth, nil
}

func GetRefreshTokenFromDb(permamentId, userAgent string) (string, bool, error) {
	row := Db.QueryRow(refreshTokenSelectQuery, permamentId, userAgent)
	var token string
	var cancelled bool
	err := row.Scan(&token, &cancelled)
	if err != nil {
		return "", false, errors.WithStack(err)
	}
	return token, cancelled, nil
}

func GetPermanentIdAndCheckPasswordFromDb(login, password string) (string, error) {
	row := Db.QueryRow(permanentIdAndPasswordHashSelectQuery, login)
	var permanentId, passwordHash string
	err := row.Scan(&permanentId, &passwordHash)
	if err != nil {
		return "", errors.WithStack(err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		err := errors.New("password invalid")
		traceErr := errors.WithStack(err)
		return "", errors.WithStack(traceErr)
	}
	return permanentId, nil
}

func GetPermanentIdFromDbByTemporaryId(temporaryId string) (string, error) {
	row := Db.QueryRow(permanentIdByTemporaryIdSelectQuery, temporaryId)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}

func SetLoginInDbTx(tx *sql.Tx, permanentId, login string) error {
	_, err := tx.Exec(loginUpdateQuery, permanentId)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(loginInsertQuery, permanentId, login, false)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func SetEmailInDbTx(tx *sql.Tx, permanentId, email string, yauth bool) error {
	_, err := tx.Exec(emailUpdateQuery, permanentId, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(emailInsertQuery, permanentId, email, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordInDbTx(tx *sql.Tx, permanentId, password string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(passwordHashUpdateQuery, permanentId)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(passwordHashInsertQuery, permanentId, passwordHash, false)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func SetTemporaryIdInDbTx(tx *sql.Tx, permanentId, temporaryId, userAgent string) error {
	_, err := tx.Exec(temporaryIdUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(temporaryIdInsertQuery, permanentId, temporaryId, userAgent, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenInDbTx(tx *sql.Tx, permanentId, refreshToken, userAgent string) error {
	_, err := tx.Exec(refreshTokenUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(refreshTokenInsertQuery, permanentId, refreshToken, userAgent, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryIdCancelledInDbTx(tx *sql.Tx, permanentId, userAgent string) error {
	_, err := tx.Exec(temporaryIdUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenCancelledInDbTx(tx *sql.Tx, permanentId, userAgent string) error {
	_, err := tx.Exec(refreshTokenUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenInDb(token string) error {
	_, err := Db.Exec(passwordResetTokenInsertQuery, token, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func IsTemporaryIdCancelled(temporaryId string) error {
	row := Db.QueryRow(temporaryIdCancelledSelectQuery, temporaryId)
	var temporaryIdCancelled bool
	err := row.Scan(&temporaryIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	if temporaryIdCancelled {
		err := errors.New("temporaryId cancelled")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	return nil
}

func IsPasswordResetTokenCancelled(token string) error {
	row := Db.QueryRow(passwordResetTokenCancelledSelectQuery, token)
	var passwordResetTokenCancelled bool
	err := row.Scan(&passwordResetTokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	if passwordResetTokenCancelled {
		err := errors.New("passwordResetToken cancelled")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	return nil
}

func IfTemporaryIdNotCancelledGetPermanentId(temporaryId string) (string, error) {
	row := Db.QueryRow(temporaryIdNotCancelledSelectQuery, temporaryId)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}
