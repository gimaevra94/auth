// Package data предоставляет функции для работы с базой данных сессиями и cookie.
//
// Файл содержит:
//   - SQL-запросы для работы с таблицами пользователей
//   - Функции подключения и управления соединением с БД
//   - Функции CRUD-операций для сущностей:
//   - permanentId (постоянный идентификатор пользователя)
//   - login (логин пользователя)
//   - email (электронная почта)
//   - password_hash (хеш пароля)
//   - temporary_id (временный идентификатор сессии)
//   - refresh_token (токен обновления)
//   - reset_token (токен сброса пароля)
//
// Все операции используют мягкое удаление через поле cancelled.
package data

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// SQL-запросы для работы с таблицами пользователей
const (
	PermanentIdByEmailSelectQuery          = "select permanentId from email where email = ? and yauth = ? and cancelled = false"
	PermanentIdByLoginSelectQuery          = "select permanentId from login where login = ? and cancelled = false"
	UniqueUserAgentsSelectQuery            = "select userAgent from temporary_id where permanentId = ?"
	TemporaryIdSelectQuery                 = "select permanentId, userAgent from temporary_id where temporaryId = ?"
	EmailSelectQuery                       = "select email from email where permanentId = ? and cancelled = false"
	RefreshTokenSelectQuery                = "select token from refresh_token where permanentId = ? and userAgent = ? and cancelled = false"
	LoginUpdateQuery                       = "update login set cancelled = true where permanentId = ? and cancelled = false"
	LoginInsertQuery                       = "insert into login (permanentId, login, cancelled) values (?, ?, ?)"
	EmailUpdateQuery                       = "update email set cancelled = true where permanentId = ? and yauth = ? and cancelled = false"
	EmailInsertQuery                       = "insert into email (permanentId, email, yauth, cancelled) values (?, ?, ?, ?)"
	PasswordHashUpdateQuery                = "update password_hash set cancelled = true where permanentId = ? and cancelled = false"
	PasswordHashInsertQuery                = "insert into password_hash (permanentId, passwordHash, cancelled) values (?, ?, ?)"
	TemporaryIdUpdateQuery                 = "update temporary_id set cancelled = true where permanentId = ? and userAgent = ? and yauth = ? and cancelled = false"
	TemporaryIdInsertQuery                 = "insert into temporary_id (permanentId, temporaryId, userAgent,yauth,cancelled) values (?, ?, ?, ?, ?)"
	RefreshTokenUpdateQuery                = "update refresh_token set cancelled = true where permanentId = ? and userAgent = ? and yauth = ? and cancelled = false"
	RefreshTokenInsertQuery                = "insert into refresh_token (permanentId, token, userAgent,yauth,cancelled) values (?, ?, ?, ?, ?)"
	TemporaryIdCancelledUpdateQuery        = "update temporary_id set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	RefreshTokenCancelledUpdateQuery       = "update refresh_token set cancelled = true where permanentId = ? and userAgent = ? and cancelled = false"
	PasswordResetTokenInsertQuery          = "insert into reset_token (token, cancelled) values (?, ?)"
	IsOKPasswordHashInDbSelectQuery        = "select passwordHash from password_hash where permanentId = ? and cancelled = false"
	PasswordResetTokenCancelledSelectQuery = "select cancelled from reset_token where token = ? and cancelled = false"
	TemporaryIdCancelledSelectQuery        = "select cancelled from temporary_id where temporaryId = ? and cancelled = false"
)

// Db - глобальная переменная для хранения соединения с базой данных
var Db *sql.DB

// DbConn устанавливает соединение с базой данных MySQL.
//
// Использует переменные окружения для подключения:
//   - DB_PASSWORD: пароль пользователя root
//   - DB_SSL_CA: путь к файлу корневого сертификата (обязательно)
//   - DB_SSL_CERT: путь к файлу клиентского сертификата (опционально)
//   - DB_SSL_KEY: путь к файлу клиентского ключа (опционально)
//
// Если DB_SSL_CERT и DB_SSL_KEY не заданы, используется только проверка сертификата сервера (односторонняя аутентификация).
// Если заданы, используется mutual TLS (двусторонняя аутентификация).
//
// Возвращает ошибку, если не удалось установить соединение.
func DbConn() error {
	caCertPath := os.Getenv("DB_SSL_CA")
	rootCertPool := x509.NewCertPool()
	pem, err := os.ReadFile(caCertPath)
	if err != nil {
		return errors.WithStack(err)
	}

	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return errors.New("failed to append PEM.")
	}

	tlsConfig := &tls.Config{
		RootCAs: rootCertPool,
	}

	// Проверяем, заданы ли переменные для клиентского сертификата и ключа
	clientCertPath := os.Getenv("DB_SSL_CERT")
	clientKeyPath := os.Getenv("DB_SSL_KEY")

	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return errors.WithStack(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	mysql.RegisterTLSConfig("custom", tlsConfig)
	DbPassword := []byte(os.Getenv("DB_PASSWORD"))
	cfg := mysql.Config{
		User:      "root",
		Passwd:    string(DbPassword),
		Net:       "tcp",
		Addr:      "db:3306",
		DBName:    "db",
		TLSConfig: "custom",
	}

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

// DbClose закрывает соединение с базой данных и обнуляет глобальную переменную.
func DbClose() {
	if Db != nil {
		Db.Close()
		Db = nil
	}
}

// --- Остальная часть кода остается без изменений ---

var GetPermanentIdFromDbByEmail = func(email string, yauth bool) (string, error) {
	var permanentId string
	row := Db.QueryRow(PermanentIdByEmailSelectQuery, email, yauth)
	err := row.Scan(&permanentId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}

var GetPermanentIdFromDbByLogin = func(login string) (string, error) {
	row := Db.QueryRow(PermanentIdByLoginSelectQuery, login)
	var permanentId string
	err := row.Scan(&permanentId)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}

var GetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
	rows, err := Db.Query(UniqueUserAgentsSelectQuery, permanentId)
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
	row := Db.QueryRow(TemporaryIdSelectQuery, temporaryId)
	var permanentId, userAgent string
	err := row.Scan(&permanentId, &userAgent)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	return permanentId, userAgent, nil
}

func GetEmailFromDb(permamentId string) (string, error) {
	row := Db.QueryRow(EmailSelectQuery, permamentId)
	var email string
	err := row.Scan(&email)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return email, nil
}

func GetRefreshTokenFromDb(permamentId, userAgent string) (string, error) {
	row := Db.QueryRow(RefreshTokenSelectQuery, permamentId, userAgent)
	var token string
	err := row.Scan(&token)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return token, nil
}

var SetLoginInDbTx = func(tx *sql.Tx, permanentId, login string) error {
	_, err := tx.Exec(LoginUpdateQuery, permanentId)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(LoginInsertQuery, permanentId, login, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetEmailInDbTx = func(tx *sql.Tx, permanentId, email string, yauth bool) error {
	_, err := tx.Exec(EmailUpdateQuery, permanentId, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(EmailInsertQuery, permanentId, email, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetEmailInDb = func(permanentId, email string, yauth bool) error {
	_, err := Db.Exec(EmailUpdateQuery, permanentId, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = Db.Exec(EmailInsertQuery, permanentId, email, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetPasswordInDbTx = func(tx *sql.Tx, permanentId, password string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(PasswordHashUpdateQuery, permanentId)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(PasswordHashInsertQuery, permanentId, passwordHash, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
	_, err := tx.Exec(TemporaryIdUpdateQuery, permanentId, userAgent, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(TemporaryIdInsertQuery, permanentId, temporaryId, userAgent, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
	_, err := tx.Exec(RefreshTokenUpdateQuery, permanentId, userAgent, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(RefreshTokenInsertQuery, permanentId, refreshToken, userAgent, yauth, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetTemporaryIdCancelledInDbTx = func(tx *sql.Tx, permanentId, userAgent string) error {
	_, err := tx.Exec(TemporaryIdCancelledUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetRefreshTokenCancelledInDbTx = func(tx *sql.Tx, permanentId, userAgent string) error {
	_, err := tx.Exec(RefreshTokenCancelledUpdateQuery, permanentId, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

var SetPasswordResetTokenInDb = func(token string) error {
	_, err := Db.Exec(PasswordResetTokenInsertQuery, token, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func IsTemporaryIdCancelled(temporaryId string) error {
	row := Db.QueryRow(TemporaryIdCancelledSelectQuery, temporaryId)
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

var IsPasswordResetTokenCancelled = func(token string) error {
	row := Db.QueryRow(PasswordResetTokenCancelledSelectQuery, token)
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

var IsOKPasswordHashInDb = func(permanentId, password string) error {
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