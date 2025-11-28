package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	permanentIdByEmailSelectQuery          = "select permanentId from email where email = ? and yauth = ? and cancelled = false"
	permanentIdByLoginSelectQuery          = "select permanentId from login where login = ? and cancelled = false"
	uniqueUserAgentsSelectQuery            = "select userAgent from temporary_id where permanentId = ?"
	temporaryIdSelectQuery                 = "select permanentId, userAgent from temporary_id where temporaryId = ?"
	emailSelectQuery                       = "select email from email where permanentId = ? and cancelled = false"
	refreshTokenSelectQuery                = "select token from refresh_token where permanentId = ? and userAgent = ? and cancelled = false"
	loginUpdateQuery                       = "update login set cancelled = true where permanentId = ? and cancelled = false"
	loginInsertQuery                       = "insert into login (permanentId, login, cancelled) values (?, ?, ?)"
	emailUpdateQuery                       = "update email set cancelled = true where permanentId = ? and yauth = ? and cancelled = false"
	emailInsertQuery                       = "insert into email (permanentId, email, yauth, cancelled) values (?, ?, ?, ?)"
	passwordHashUpdateQuery                = "update password_hash set cancelled = true where permanentId = ? and cancelled = false"
	passwordHashInsertQuery                = "insert into password_hash (permanentId, passwordHash, cancelled) values (?, ?, ?)"
	temporaryIdUpdateQuery                 = "update temporary_id set cancelled = true where permanentId = ? and userAgent = ? and yauth = ? and cancelled = false"
	temporaryIdInsertQuery                 = "insert into temporary_id (permanentId, temporaryId, userAgent,yauth,cancelled) values (?, ?, ?, ?, ?)"
	refreshTokenUpdateQuery                = "update refresh_token set cancelled = true where permanentId = ? and userAgent = ? and yauth = ? and cancelled = false"
	refreshTokenInsertQuery                = "insert into refresh_token (permanentId, token, userAgent,yauth,cancelled) values (?, ?, ?, ?, ?)"
	temporaryIdCancelledUpdateQuery        = "update temporary_id set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	refreshTokenCancelledUpdateQuery       = "update refresh_token set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	passwordResetTokenInsertQuery          = "insert into reset_token (token, cancelled) values (?, ?)"
	IsOKPasswordHashInDbSelectQuery        = "select passwordHash from password_hash where permanentId = ? and cancelled = false"
	passwordResetTokenCancelledSelectQuery = "select cancelled from reset_token where token = ? and cancelled = false"
	temporaryIdCancelledSelectQuery        = "select cancelled from temporary_id where temporaryId = ? and cancelled = false"
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

func GetPermanentIdFromDbByLogin(login string) (string, error) {
	row := Db.QueryRow(permanentIdByLoginSelectQuery, login)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
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

func GetEmailFromDb(permamentId string) (string, error) {
	row := Db.QueryRow(emailSelectQuery, permamentId)
	var email string
	err := row.Scan(&email)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return email, nil
}

func GetRefreshTokenFromDb(permamentId, userAgent string) (string, error) {
	row := Db.QueryRow(refreshTokenSelectQuery, permamentId, userAgent)
	var token string
	err := row.Scan(&token)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return token, nil
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

func SetEmailInDb(permanentId, email string, yauth bool) error {
	_, err := Db.Exec(emailUpdateQuery, permanentId, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = Db.Exec(emailInsertQuery, permanentId, email, yauth, false)
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

func SetTemporaryIdInDbTx(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
	_, err := tx.Exec(temporaryIdUpdateQuery, permanentId, userAgent, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(temporaryIdInsertQuery, permanentId, temporaryId, userAgent, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenInDbTx(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
	_, err := tx.Exec(refreshTokenUpdateQuery, permanentId, userAgent, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(refreshTokenInsertQuery, permanentId, refreshToken, userAgent, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryIdCancelledInDbTx(tx *sql.Tx, permanentId, userAgent string) error {
	_, err := tx.Exec(temporaryIdCancelledUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenCancelledInDbTx(tx *sql.Tx, permanentId, userAgent string) error {
	_, err := tx.Exec(refreshTokenCancelledUpdateQuery, permanentId, userAgent)
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
	var cancelled bool
	err := row.Scan(&cancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	if cancelled {
		err := errors.New("temporaryId cancelled")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	return nil
}

func IsPasswordResetTokenCancelled(token string) error {
	row := Db.QueryRow(passwordResetTokenCancelledSelectQuery, token)
	var cancelled bool
	err := row.Scan(&cancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	if cancelled {
		err := errors.New("passwordResetToken cancelled")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	return nil
}

func IsOKPasswordHashInDb(permanentId, password string) error {
	row := Db.QueryRow(IsOKPasswordHashInDbSelectQuery, permanentId)
	var passwordHash string
	err := row.Scan(&passwordHash)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		err := errors.New("password invalid")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	return nil
}
