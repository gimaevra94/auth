package data

import (
	"database/sql"
	"log"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	permanentIdByEmailSelectQuery       = "select permanentId from email where email = ? and yauth = ? and cancelled = false"
	permanentIdByTemporaryIdSelectQuery = "select permanentId from temporary_id where temporaryId = ? and cancelled = false"
	permanentIdByLoginSelectQuery       = "select permanentId from login where login = ? and cancelled = false"
	uniqueUserAgentsSelectQuery         = "select userAgent from temporary_id where permanentId = ?"
	temporaryIdSelectQuery              = "select permanentId, userAgent from temporary_id where temporaryId = ?"
	emailSelectQuery                    = "select email, yauth from email where permanentId = ? and cancelled = false"
	refreshTokenSelectQuery             = "select token, cancelled from refresh_token where permanentId = ? and userAgent = ?"
	loginUpdateQuery                    = "update login set cancelled = true where permanentId = ? and cancelled = false"
	loginInsertQuery                    = "insert into login (permanentId, login, cancelled) values (?, ?, ?)"
	emailUpdateQuery                    = "update email set cancelled = true where permanentId = ? and yauth = ? and cancelled = false"
	emailInsertQuery                    = "insert into email (permanentId, email, yauth, cancelled) values (?, ?, ?, ?)"
	passwordHashUpdateQuery          = "update password_hash set cancelled = true where permanentId = ? and cancelled = false"
	passwordHashInsertQuery          = "insert into password_hash (permanentId, passwordHash, cancelled) values (?, ?, ?)"
	temporaryIdUpdateQuery           = "update temporary_id set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	temporaryIdInsertQuery           = "insert into temporary_id (permanentId, temporaryId, userAgent,cancelled) values (?, ?, ?, ?)"
	refreshTokenUpdateQuery          = "update refresh_token set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	refreshTokenInsertQuery          = "insert into refresh_token (permanentId, token, userAgent,cancelled) values (?, ?, ?, ?)"
	
	temporaryIdCancelledUpdateQuery  = "update temporary_id set cancelled = true where temporaryId = ? and cancelled = false"
	refreshTokenCancelledUpdateQuery = "update refresh_token set cancelled = true where token = ? and cancelled = false"
	passwordResetTokenInsertQuery    = "insert into password_reset_token (token, cancelled) values (?, ?)"
	IsOKPasswordHashInDbSelectQuery        = "select passwordHash from password_hash where permanentId = ? and cancelled = false"
	temporaryIdNotCancelledSelectQuery     = "select permanentId from temporary_id where temporaryId = ? and cancelled = false"
	passwordResetTokenCancelledSelectQuery = "select cancelled from password_reset_token where token = ? and cancelled = false"
)

var Db *sql.DB

func DbConn() error {
	log.Printf("[DEBUG] Attempting to connect to database")
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
		log.Printf("[ERROR] Failed to open database: %v", err)
		return errors.WithStack(err)
	}
	if err = Db.Ping(); err != nil {
		log.Printf("[ERROR] Failed to ping database: %v", err)
		Db.Close()
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully connected to database")
	return nil
}

func DbClose() {
	log.Printf("[DEBUG] Closing database connection")
	if Db != nil {
		Db.Close()
	}
}

func GetPermanentIdFromDbByEmail(yauth bool, email string) (string, error) {
	log.Printf("[DEBUG] GetPermanentIdFromDbByEmail called with email: %s, yauth: %t", email, yauth)
	var permanentId string
	row := Db.QueryRow(permanentIdByEmailSelectQuery, yauth, email)
	err := row.Scan(&permanentId)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[DEBUG] No rows found for email: %s, yauth: %t", email, yauth)
			return "", errors.WithStack(err)
		}
		log.Printf("[ERROR] Error querying permanentId by email: %v", err)
		return "", errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found permanentId: %s for email: %s, yauth: %t", permanentId, email, yauth)
	return permanentId, nil
}

func GetPermanentIdFromDbByTemporaryId(temporaryId string) (string, error) {
	log.Printf("[DEBUG] GetPermanentIdFromDbByTemporaryId called with temporaryId: %s", temporaryId)
	row := Db.QueryRow(permanentIdByTemporaryIdSelectQuery, temporaryId)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
		log.Printf("[ERROR] Error querying permanentId by temporaryId: %v", err)
		return "", errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found permanentId: %s for temporaryId: %s", permanentId, temporaryId)
	return permanentId, nil
}

func GetPermanentIdFromDbByLogin(login string) (string, error) {
	log.Printf("[DEBUG] GetPermanentIdFromDbByLogin called with login: %s", login)
	row := Db.QueryRow(permanentIdByLoginSelectQuery, login)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
		log.Printf("[ERROR] Error querying permanentId by login: %v", err)
		return "", errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found permanentId: %s for login: %s", permanentId, login)
	return permanentId, nil
}

func GetUniqueUserAgentsFromDb(permanentId string) ([]string, error) {
	log.Printf("[DEBUG] GetUniqueUserAgentsFromDb called with permanentId: %s", permanentId)
	rows, err := Db.Query(uniqueUserAgentsSelectQuery, permanentId)
	if err != nil {
		log.Printf("[ERROR] Error querying unique user agents: %v", err)
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	var uniqueUserAgents []string
	for rows.Next() {
		var userAgent string
		if err := rows.Scan(&userAgent); err != nil {
			log.Printf("[ERROR] Error scanning user agent: %v", err)
			return nil, errors.WithStack(err)
		}
		uniqueUserAgents = append(uniqueUserAgents, userAgent)
		log.Printf("[DEBUG] Scanned user agent: %s", userAgent)
	}
	log.Printf("[DEBUG] Found %d unique user agents for permanentId: %s", len(uniqueUserAgents), permanentId)
	return uniqueUserAgents, nil
}

func GetTemporaryIdKeysFromDb(temporaryId string) (string, string, error) {
	log.Printf("[DEBUG] GetTemporaryIdKeysFromDb called with temporaryId: %s", temporaryId)
	row := Db.QueryRow(temporaryIdSelectQuery, temporaryId)
	var permanentId, userAgent string
	err := row.Scan(&permanentId, &userAgent)
	if err != nil {
		log.Printf("[ERROR] Error querying temporaryId keys: %v", err)
		return "", "", errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found permanentId: %s, userAgent: %s for temporaryId: %s", permanentId, userAgent, temporaryId)
	return permanentId, userAgent, nil
}

func GetEmailFromDb(permamentId string) (string, bool, error) {
	log.Printf("[DEBUG] GetEmailFromDb called with permamentId: %s", permamentId)
	row := Db.QueryRow(emailSelectQuery, permamentId)
	var email string
	var yauth bool
	err := row.Scan(&email, &yauth)
	if err != nil {
		log.Printf("[ERROR] Error querying email: %v", err)
		return "", false, errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found email: %s, yauth: %t for permamentId: %s", email, yauth, permamentId)
	return email, yauth, nil
}

func GetRefreshTokenFromDb(permamentId, userAgent string) (string, bool, error) {
	log.Printf("[DEBUG] GetRefreshTokenFromDb called with permamentId: %s, userAgent: %s", permamentId, userAgent)
	row := Db.QueryRow(refreshTokenSelectQuery, permamentId, userAgent)
	var token string
	var cancelled bool
	err := row.Scan(&token, &cancelled)
	if err != nil {
		log.Printf("[ERROR] Error querying refresh token: %v", err)
		return "", false, errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found token: %s, cancelled: %t for permamentId: %s, userAgent: %s", token, cancelled, permamentId, userAgent)
	return token, cancelled, nil
}

func SetLoginInDbTx(tx *sql.Tx, permanentId, login string) error {
	log.Printf("[DEBUG] SetLoginInDbTx called with permanentId: %s, login: %s", permanentId, login)
	_, err := tx.Exec(loginUpdateQuery, permanentId)
	if err != nil {
		log.Printf("[ERROR] Error updating login: %v", err)
		return errors.WithStack(err)
	}
	_, err = tx.Exec(loginInsertQuery, permanentId, login, false)
	if err != nil {
		log.Printf("[ERROR] Error inserting login: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully set login in DB for permanentId: %s, login: %s", permanentId, login)
	return nil
}

func SetEmailInDbTx(tx *sql.Tx, permanentId, email string, yauth bool) error {
	log.Printf("[DEBUG] SetEmailInDbTx called with permanentId: %s, email: %s, yauth: %t", permanentId, email, yauth)
	_, err := tx.Exec(emailUpdateQuery, permanentId, yauth)
	if err != nil {
		log.Printf("[ERROR] Error updating email: %v", err)
		return errors.WithStack(err)
	}
	_, err = tx.Exec(emailInsertQuery, permanentId, email, yauth, false)
	if err != nil {
		log.Printf("[ERROR] Error inserting email: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully set email in DB for permanentId: %s, email: %s, yauth: %t", permanentId, email, yauth)
	return nil
}

func SetPasswordInDbTx(tx *sql.Tx, permanentId, password string) error {
	log.Printf("[DEBUG] SetPasswordInDbTx called with permanentId: %s", permanentId)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[ERROR] Error generating password hash: %v", err)
		return errors.WithStack(err)
	}
	_, err = tx.Exec(passwordHashUpdateQuery, permanentId)
	if err != nil {
		log.Printf("[ERROR] Error updating password hash: %v", err)
		return errors.WithStack(err)
	}
	_, err = tx.Exec(passwordHashInsertQuery, permanentId, passwordHash, false)
	if err != nil {
		log.Printf("[ERROR] Error inserting password hash: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully set password in DB for permanentId: %s", permanentId)
	return nil
}

func SetTemporaryIdInDbTx(tx *sql.Tx, permanentId, temporaryId, userAgent string) error {
	log.Printf("[DEBUG] SetTemporaryIdInDbTx called with permanentId: %s, temporaryId: %s, userAgent: %s", permanentId, temporaryId, userAgent)
	_, err := tx.Exec(temporaryIdUpdateQuery, permanentId, userAgent)
	if err != nil {
		log.Printf("[ERROR] Error updating temporaryId: %v", err)
		return errors.WithStack(err)
	}
	_, err = tx.Exec(temporaryIdInsertQuery, permanentId, temporaryId, userAgent, false)
	if err != nil {
		log.Printf("[ERROR] Error inserting temporaryId: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully set temporaryId in DB for permanentId: %s, temporaryId: %s, userAgent: %s", permanentId, temporaryId, userAgent)
	return nil
}

func SetRefreshTokenInDbTx(tx *sql.Tx, permanentId, refreshToken, userAgent string) error {
	log.Printf("[DEBUG] SetRefreshTokenInDbTx called with permanentId: %s, refreshToken: %s, userAgent: %s", permanentId, refreshToken, userAgent)
	_, err := tx.Exec(refreshTokenUpdateQuery, permanentId, userAgent)
	if err != nil {
		log.Printf("[ERROR] Error updating refresh token: %v", err)
		return errors.WithStack(err)
	}
	_, err = tx.Exec(refreshTokenInsertQuery, permanentId, refreshToken, userAgent, false)
	if err != nil {
		log.Printf("[ERROR] Error inserting refresh token: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully set refresh token in DB for permanentId: %s, refreshToken: %s, userAgent: %s", permanentId, refreshToken, userAgent)
	return nil
}

func SetTemporaryIdCancelledInDbTx(tx *sql.Tx, permanentId, userAgent string) error {
	log.Printf("[DEBUG] SetTemporaryIdCancelledInDbTx called with permanentId: %s, userAgent: %s", permanentId, userAgent)
	_, err := tx.Exec(temporaryIdCancelledSelectQuery, permanentId, userAgent)
	if err != nil {
		log.Printf("[ERROR] Error updating temporaryId to cancelled: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully cancelled temporaryId in DB for permanentId: %s, userAgent: %s", permanentId, userAgent)
	return nil
}

func SetRefreshTokenCancelledInDbTx(tx *sql.Tx, permanentId, userAgent string) error {
	log.Printf("[DEBUG] SetRefreshTokenCancelledInDbTx called with permanentId: %s, userAgent: %s", permanentId, userAgent)
	_, err := tx.Exec(refreshTokenCancelledSelectQuery, permanentId, userAgent)
	if err != nil {
		log.Printf("[ERROR] Error updating refresh token to cancelled: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully cancelled refresh token in DB for permanentId: %s, userAgent: %s", permanentId, userAgent)
	return nil
}

func SetPasswordResetTokenInDb(token string) error {
	log.Printf("[DEBUG] SetPasswordResetTokenInDb called with token: %s", token)
	_, err := Db.Exec(passwordResetTokenInsertQuery, token, false)
	if err != nil {
		log.Printf("[ERROR] Error inserting password reset token: %v", err)
		return errors.WithStack(err)
	}
	log.Printf("[DEBUG] Successfully set password reset token in DB: %s", token)
	return nil
}

func IsTemporaryIdCancelled(temporaryId string) error {
	log.Printf("[DEBUG] IsTemporaryIdCancelled called with temporaryId: %s", temporaryId)
	row := Db.QueryRow(temporaryIdCancelledSelectQuery, temporaryId)
	var temporaryIdCancelled bool
	err := row.Scan(&temporaryIdCancelled)
	if err != nil {
		log.Printf("[ERROR] Error querying temporaryId cancellation status: %v", err)
		return errors.WithStack(err)
	}
	if temporaryIdCancelled {
		log.Printf("[DEBUG] temporaryId %s is cancelled", temporaryId)
		err := errors.New("temporaryId cancelled")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	log.Printf("[DEBUG] temporaryId %s is not cancelled", temporaryId)
	return nil
}

func IsPasswordResetTokenCancelled(token string) error {
	log.Printf("[DEBUG] IsPasswordResetTokenCancelled called with token: %s", token)
	row := Db.QueryRow(passwordResetTokenCancelledSelectQuery, token)
	var passwordResetTokenCancelled bool
	err := row.Scan(&passwordResetTokenCancelled)
	if err != nil {
		log.Printf("[ERROR] Error querying password reset token cancellation status: %v", err)
		return errors.WithStack(err)
	}
	if passwordResetTokenCancelled {
		log.Printf("[DEBUG] passwordResetToken %s is cancelled", token)
		err := errors.New("passwordResetToken cancelled")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	log.Printf("[DEBUG] passwordResetToken %s is not cancelled", token)
	return nil
}

func IfTemporaryIdNotCancelledGetPermanentId(temporaryId string) (string, error) {
	log.Printf("[DEBUG] IfTemporaryIdNotCancelledGetPermanentId called with temporaryId: %s", temporaryId)
	row := Db.QueryRow(temporaryIdNotCancelledSelectQuery, temporaryId)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
		log.Printf("[ERROR] Error querying permanentId from temporaryId: %v", err)
		return "", errors.WithStack(err)
	}
	log.Printf("[DEBUG] Found permanentId: %s from temporaryId: %s (not cancelled)", permanentId, temporaryId)
	return permanentId, nil
}

func IsOKPasswordHashInDb(permanentId, password string) error {
	log.Printf("[DEBUG] IsOKPasswordHashInDb called with permanentId: %s", permanentId)
	row := Db.QueryRow(IsOKPasswordHashInDbSelectQuery, permanentId)
	var passwordHash string
	err := row.Scan(&passwordHash)
	if err != nil {
		log.Printf("[ERROR] Error querying password hash: %v", err)
		return errors.WithStack(err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		log.Printf("[DEBUG] Password validation failed for permanentId: %s", permanentId)
		err := errors.New("password invalid")
		traceErr := errors.WithStack(err)
		return errors.WithStack(traceErr)
	}
	log.Printf("[DEBUG] Password validation succeeded for permanentId: %s", permanentId)
	return nil
}
