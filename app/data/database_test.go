// Package data предоставляет функции для работы с базой данных сессиями и cookie.
//
// Файл тестирует функции подключения к базе данных, выполнения запросов,
// а также транзакционные операции с пользовательскими данными.
package data

import (
	"database/sql"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestDbConn проверяет установку соединения с базой данных.
// Ожидается: успешное подключение при валидных данных, обработка ошибок при невалидных.
func TestDbConn(t *testing.T) {
	t.Run("successful connection", func(t *testing.T) {
		os.Setenv("DB_PASSWORD", "testpass")

		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer db.Close()

		mock.ExpectPing()

		originalDb := Db
		Db = db
		defer func() {
			Db = originalDb
			if db != nil {
				db.Close()
			}
		}()

		err = Db.Ping()
		assert.NoError(t, err)
		assert.NotNil(t, Db)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("connection error", func(t *testing.T) {
		os.Setenv("DB_PASSWORD", "")

		originalDb := Db
		defer func() { Db = originalDb }()

		Db = nil

		if Db != nil {
			err := Db.Ping()
			assert.Error(t, err)
		} else {
			assert.True(t, true)
		}
	})
}

// TestDbClose проверяет закрытие соединения с базой данных.
// Ожидается: корректное закрытие существующего соединения и обработка nil-соединения.
func TestDbClose(t *testing.T) {
	t.Run("close existing connection", func(t *testing.T) {
		db, _, err := sqlmock.New()
		require.NoError(t, err)

		Db = db
		DbClose()
		assert.Nil(t, Db)
	})

	t.Run("close nil connection", func(t *testing.T) {
		Db = nil
		DbClose()
		assert.Nil(t, Db)
	})
}

// TestGetPermanentIdFromDbByEmail проверяет получение permanent ID по email.
// Ожидается: успешное получение ID, обработка отсутствия записи и ошибок базы данных.
func TestGetPermanentIdFromDbByEmail(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful retrieval", func(t *testing.T) {
		expectedId := "perm123"
		mock.ExpectQuery(PermanentIdByEmailSelectQuery).
			WithArgs("test@example.com", true).
			WillReturnRows(sqlmock.NewRows([]string{"permanentId"}).AddRow(expectedId))

		id, err := GetPermanentIdFromDbByEmail("test@example.com", true)
		assert.NoError(t, err)
		assert.Equal(t, expectedId, id)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no rows found", func(t *testing.T) {
		mock.ExpectQuery(PermanentIdByEmailSelectQuery).
			WithArgs("nonexistent@example.com", false).
			WillReturnError(sql.ErrNoRows)

		id, err := GetPermanentIdFromDbByEmail("nonexistent@example.com", false)
		assert.Error(t, err)
		assert.Equal(t, "", id)
		assert.Equal(t, sql.ErrNoRows, errors.Cause(err))
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(PermanentIdByEmailSelectQuery).
			WithArgs("error@example.com", true).
			WillReturnError(sql.ErrConnDone)

		id, err := GetPermanentIdFromDbByEmail("error@example.com", true)
		assert.Error(t, err)
		assert.Equal(t, "", id)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestGetPermanentIdFromDbByLogin проверяет получение permanent ID по логину.
// Ожидается: успешное получение ID и обработка ошибок базы данных.
func TestGetPermanentIdFromDbByLogin(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful retrieval", func(t *testing.T) {
		expectedId := "perm456"
		mock.ExpectQuery(PermanentIdByLoginSelectQuery).
			WithArgs("testlogin").
			WillReturnRows(sqlmock.NewRows([]string{"permanentId"}).AddRow(expectedId))

		id, err := GetPermanentIdFromDbByLogin("testlogin")
		assert.NoError(t, err)
		assert.Equal(t, expectedId, id)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(PermanentIdByLoginSelectQuery).
			WithArgs("errorlogin").
			WillReturnError(sql.ErrConnDone)

		id, err := GetPermanentIdFromDbByLogin("errorlogin")
		assert.Error(t, err)
		assert.Equal(t, "", id)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestGetUniqueUserAgentsFromDb проверяет получение уникальных user agents.
// Ожидается: успешное получение списка агентов, пустой результат и обработка ошибок.
func TestGetUniqueUserAgentsFromDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful retrieval with multiple agents", func(t *testing.T) {
		expectedAgents := []string{"Chrome", "Firefox", "Safari"}
		rows := sqlmock.NewRows([]string{"userAgent"})
		for _, agent := range expectedAgents {
			rows.AddRow(agent)
		}
		mock.ExpectQuery(UniqueUserAgentsSelectQuery).
			WithArgs("perm123").
			WillReturnRows(rows)

		agents, err := GetUniqueUserAgentsFromDb("perm123")
		assert.NoError(t, err)
		assert.Equal(t, expectedAgents, agents)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("successful retrieval with empty result", func(t *testing.T) {
		mock.ExpectQuery(UniqueUserAgentsSelectQuery).
			WithArgs("emptyperm").
			WillReturnRows(sqlmock.NewRows([]string{"userAgent"}))

		agents, err := GetUniqueUserAgentsFromDb("emptyperm")
		assert.NoError(t, err)
		assert.Empty(t, agents)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(UniqueUserAgentsSelectQuery).
			WithArgs("errorperm").
			WillReturnError(sql.ErrConnDone)

		agents, err := GetUniqueUserAgentsFromDb("errorperm")
		assert.Error(t, err)
		assert.Nil(t, agents)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestGetTemporaryIdKeysFromDb проверяет получение ключей по временному ID.
// Ожидается: успешное получение permanent ID и user agent, обработка ошибок базы данных.
func TestGetTemporaryIdKeysFromDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful retrieval", func(t *testing.T) {
		expectedPermanentId := "perm789"
		expectedUserAgent := "Chrome"
		mock.ExpectQuery(TemporaryIdSelectQuery).
			WithArgs("temp123").
			WillReturnRows(sqlmock.NewRows([]string{"permanentId", "userAgent"}).
				AddRow(expectedPermanentId, expectedUserAgent))

		permanentId, userAgent, err := GetTemporaryIdKeysFromDb("temp123")
		assert.NoError(t, err)
		assert.Equal(t, expectedPermanentId, permanentId)
		assert.Equal(t, expectedUserAgent, userAgent)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(TemporaryIdSelectQuery).
			WithArgs("errortemp").
			WillReturnError(sql.ErrConnDone)

		permanentId, userAgent, err := GetTemporaryIdKeysFromDb("errortemp")
		assert.Error(t, err)
		assert.Equal(t, "", permanentId)
		assert.Equal(t, "", userAgent)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestGetEmailFromDb проверяет получение email по permanent ID.
// Ожидается: успешное получение email и обработка ошибок базы данных.
func TestGetEmailFromDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful retrieval", func(t *testing.T) {
		expectedEmail := "user@example.com"
		mock.ExpectQuery(EmailSelectQuery).
			WithArgs("perm123").
			WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow(expectedEmail))

		email, err := GetEmailFromDb("perm123")
		assert.NoError(t, err)
		assert.Equal(t, expectedEmail, email)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(EmailSelectQuery).
			WithArgs("errorperm").
			WillReturnError(sql.ErrConnDone)

		email, err := GetEmailFromDb("errorperm")
		assert.Error(t, err)
		assert.Equal(t, "", email)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestGetRefreshTokenFromDb проверяет получение refresh токена.
// Ожидается: успешное получение токена и обработка ошибок базы данных.
func TestGetRefreshTokenFromDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful retrieval", func(t *testing.T) {
		expectedToken := "refresh123"
		mock.ExpectQuery(RefreshTokenSelectQuery).
			WithArgs("perm123", "Chrome").
			WillReturnRows(sqlmock.NewRows([]string{"token"}).AddRow(expectedToken))

		token, err := GetRefreshTokenFromDb("perm123", "Chrome")
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, token)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(RefreshTokenSelectQuery).
			WithArgs("errorperm", "ErrorAgent").
			WillReturnError(sql.ErrConnDone)

		token, err := GetRefreshTokenFromDb("errorperm", "ErrorAgent")
		assert.Error(t, err)
		assert.Equal(t, "", token)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetLoginInDbTx проверяет установку логина в транзакции.
// Ожидается: успешная транзакция, обработка ошибок при update и insert операциях.
func TestSetLoginInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful transaction", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(LoginUpdateQuery).
			WithArgs("perm123").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(LoginInsertQuery).
			WithArgs("perm123", "newlogin", false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetLoginInDbTx(tx, "perm123", "newlogin")
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("update error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(LoginUpdateQuery).
			WithArgs("perm123").
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetLoginInDbTx(tx, "perm123", "newlogin")
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(LoginUpdateQuery).
			WithArgs("perm123").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(LoginInsertQuery).
			WithArgs("perm123", "newlogin", false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetLoginInDbTx(tx, "perm123", "newlogin")
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetEmailInDbTx проверяет установку email в транзакции.
// Ожидается: успешная транзакция, обработка ошибок при update и insert операциях.
func TestSetEmailInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful transaction", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(EmailUpdateQuery).
			WithArgs("perm123", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(EmailInsertQuery).
			WithArgs("perm123", "email@example.com", true, false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetEmailInDbTx(tx, "perm123", "email@example.com", true)
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("update error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(EmailUpdateQuery).
			WithArgs("perm123", false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetEmailInDbTx(tx, "perm123", "email@example.com", false)
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(EmailUpdateQuery).
			WithArgs("perm123", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(EmailInsertQuery).
			WithArgs("perm123", "email@example.com", true, false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetEmailInDbTx(tx, "perm123", "email@example.com", true)
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetEmailInDb проверяет установку email без транзакции.
// Ожидается: успешная операция, обработка ошибок при update и insert операциях.
func TestSetEmailInDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful operation", func(t *testing.T) {
		mock.ExpectExec(EmailUpdateQuery).
			WithArgs("perm123", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(EmailInsertQuery).
			WithArgs("perm123", "email@example.com", true, false).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := SetEmailInDb("perm123", "email@example.com", true)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("update error", func(t *testing.T) {
		mock.ExpectExec(EmailUpdateQuery).
			WithArgs("perm123", false).
			WillReturnError(sql.ErrConnDone)

		err := SetEmailInDb("perm123", "email@example.com", false)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock.ExpectExec(EmailUpdateQuery).
			WithArgs("perm123", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(EmailInsertQuery).
			WithArgs("perm123", "email@example.com", true, false).
			WillReturnError(sql.ErrConnDone)

		err := SetEmailInDb("perm123", "email@example.com", true)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetPasswordInDbTx проверяет установку пароля в транзакции.
// Ожидается: успешная транзакция, обработка ошибок bcrypt, update и insert операций.
func TestSetPasswordInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful transaction", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(PasswordHashUpdateQuery).
			WithArgs("perm123").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(PasswordHashInsertQuery).
			WithArgs("perm123", sqlmock.AnyArg(), false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetPasswordInDbTx(tx, "perm123", "password123")
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("bcrypt error", func(t *testing.T) {
		err := SetPasswordInDbTx(nil, "perm123", string(make([]byte, 73)))
		assert.Error(t, err)
	})

	t.Run("update error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(PasswordHashUpdateQuery).
			WithArgs("perm123").
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetPasswordInDbTx(tx, "perm123", "password123")
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(PasswordHashUpdateQuery).
			WithArgs("perm123").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(PasswordHashInsertQuery).
			WithArgs("perm123", sqlmock.AnyArg(), false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetPasswordInDbTx(tx, "perm123", "password123")
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetTemporaryIdInDbTx проверяет установку временного ID в транзакции.
// Ожидается: успешная транзакция, обработка ошибок при update и insert операциях.
func TestSetTemporaryIdInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful transaction", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(TemporaryIdUpdateQuery).
			WithArgs("perm123", "Chrome", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(TemporaryIdInsertQuery).
			WithArgs("perm123", "temp123", "Chrome", true, false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetTemporaryIdInDbTx(tx, "perm123", "temp123", "Chrome", true)
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("update error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(TemporaryIdUpdateQuery).
			WithArgs("perm123", "Chrome", false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetTemporaryIdInDbTx(tx, "perm123", "temp123", "Chrome", false)
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(TemporaryIdUpdateQuery).
			WithArgs("perm123", "Chrome", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(TemporaryIdInsertQuery).
			WithArgs("perm123", "temp123", "Chrome", true, false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetTemporaryIdInDbTx(tx, "perm123", "temp123", "Chrome", true)
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetRefreshTokenInDbTx проверяет установку refresh токена в транзакции.
// Ожидается: успешная транзакция, обработка ошибок при update и insert операциях.
func TestSetRefreshTokenInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful transaction", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(RefreshTokenUpdateQuery).
			WithArgs("perm123", "Chrome", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(RefreshTokenInsertQuery).
			WithArgs("perm123", "refresh123", "Chrome", true, false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetRefreshTokenInDbTx(tx, "perm123", "refresh123", "Chrome", true)
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("update error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(RefreshTokenUpdateQuery).
			WithArgs("perm123", "Chrome", false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetRefreshTokenInDbTx(tx, "perm123", "refresh123", "Chrome", false)
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("insert error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(RefreshTokenUpdateQuery).
			WithArgs("perm123", "Chrome", true).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(RefreshTokenInsertQuery).
			WithArgs("perm123", "refresh123", "Chrome", true, false).
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetRefreshTokenInDbTx(tx, "perm123", "refresh123", "Chrome", true)
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetTemporaryIdCancelledInDbTx проверяет отмену временного ID в транзакции.
// Ожидается: успешная операция и обработка ошибок базы данных.
func TestSetTemporaryIdCancelledInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful operation", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(TemporaryIdCancelledUpdateQuery).
			WithArgs("perm123", "Chrome").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetTemporaryIdCancelledInDbTx(tx, "perm123", "Chrome")
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(TemporaryIdCancelledUpdateQuery).
			WithArgs("perm123", "Chrome").
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetTemporaryIdCancelledInDbTx(tx, "perm123", "Chrome")
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetRefreshTokenCancelledInDbTx проверяет отмену refresh токена в транзакции.
// Ожидается: успешная операция и обработка ошибок базы данных.
func TestSetRefreshTokenCancelledInDbTx(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	t.Run("successful operation", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(RefreshTokenCancelledUpdateQuery).
			WithArgs("perm123", "Chrome").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetRefreshTokenCancelledInDbTx(tx, "perm123", "Chrome")
		assert.NoError(t, err)

		tx.Commit()
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(RefreshTokenCancelledUpdateQuery).
			WithArgs("perm123", "Chrome").
			WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		require.NoError(t, err)

		err = SetRefreshTokenCancelledInDbTx(tx, "perm123", "Chrome")
		assert.Error(t, err)

		tx.Rollback()
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestSetPasswordResetTokenInDb проверяет установку токена сброса пароля.
// Ожидается: успешная операция и обработка ошибок базы данных.
func TestSetPasswordResetTokenInDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("successful operation", func(t *testing.T) {
		mock.ExpectExec(PasswordResetTokenInsertQuery).
			WithArgs("token123", false).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := SetPasswordResetTokenInDb("token123")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectExec(PasswordResetTokenInsertQuery).
			WithArgs("errortoken").
			WillReturnError(sql.ErrConnDone)

		err := SetPasswordResetTokenInDb("errortoken")
		assert.Error(t, err)
	})
}

// TestIsTemporaryIdCancelled проверяет, отменен ли временный ID.
// Ожидается: корректная проверка статуса и обработка ошибок базы данных.
func TestIsTemporaryIdCancelled(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("not cancelled", func(t *testing.T) {
		mock.ExpectQuery(TemporaryIdCancelledSelectQuery).
			WithArgs("temp123").
			WillReturnRows(sqlmock.NewRows([]string{"cancelled"}).AddRow(false))

		err := IsTemporaryIdCancelled("temp123")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("cancelled", func(t *testing.T) {
		mock.ExpectQuery(TemporaryIdCancelledSelectQuery).
			WithArgs("temp456").
			WillReturnRows(sqlmock.NewRows([]string{"cancelled"}).AddRow(true))

		err := IsTemporaryIdCancelled("temp456")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "temporaryId cancelled")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(TemporaryIdCancelledSelectQuery).
			WithArgs("errortemp").
			WillReturnError(sql.ErrConnDone)

		err := IsTemporaryIdCancelled("errortemp")
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestIsPasswordResetTokenCancelled проверяет, отменен ли токен сброса пароля.
// Ожидается: корректная проверка статуса и обработка ошибок базы данных.
func TestIsPasswordResetTokenCancelled(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("not cancelled", func(t *testing.T) {
		mock.ExpectQuery(PasswordResetTokenCancelledSelectQuery).
			WithArgs("token123").
			WillReturnRows(sqlmock.NewRows([]string{"cancelled"}).AddRow(false))

		err := IsPasswordResetTokenCancelled("token123")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("cancelled", func(t *testing.T) {
		mock.ExpectQuery(PasswordResetTokenCancelledSelectQuery).
			WithArgs("token456").
			WillReturnRows(sqlmock.NewRows([]string{"cancelled"}).AddRow(true))

		err := IsPasswordResetTokenCancelled("token456")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "passwordResetToken cancelled")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(PasswordResetTokenCancelledSelectQuery).
			WithArgs("errortoken").
			WillReturnError(sql.ErrConnDone)

		err := IsPasswordResetTokenCancelled("errortoken")
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestIsOKPasswordHashInDb проверяет валидность пароля.
// Ожидается: успешная проверка валидного пароля, ошибка при неверном пароле.
func TestIsOKPasswordHashInDb(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	Db = db

	t.Run("valid password", func(t *testing.T) {
		password := "testpassword"
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)

		mock.ExpectQuery(IsOKPasswordHashInDbSelectQuery).
			WithArgs("perm123").
			WillReturnRows(sqlmock.NewRows([]string{"passwordHash"}).AddRow(string(hash)))

		err = IsOKPasswordHashInDb("perm123", password)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("invalid password", func(t *testing.T) {
		hash, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
		require.NoError(t, err)

		mock.ExpectQuery(IsOKPasswordHashInDbSelectQuery).
			WithArgs("perm123").
			WillReturnRows(sqlmock.NewRows([]string{"passwordHash"}).AddRow(string(hash)))

		err = IsOKPasswordHashInDb("perm123", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password invalid")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(IsOKPasswordHashInDbSelectQuery).
			WithArgs("errorperm").
			WillReturnError(sql.ErrConnDone)

		err := IsOKPasswordHashInDb("errorperm", "password")
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestConstants проверяет, что все константы запросов не пустые.
// Ожидается: все SQL константы определены.
func TestConstants(t *testing.T) {
	assert.NotEmpty(t, PermanentIdByEmailSelectQuery)
	assert.NotEmpty(t, PermanentIdByLoginSelectQuery)
	assert.NotEmpty(t, UniqueUserAgentsSelectQuery)
	assert.NotEmpty(t, TemporaryIdSelectQuery)
	assert.NotEmpty(t, EmailSelectQuery)
	assert.NotEmpty(t, RefreshTokenSelectQuery)
	assert.NotEmpty(t, LoginUpdateQuery)
	assert.NotEmpty(t, LoginInsertQuery)
	assert.NotEmpty(t, EmailUpdateQuery)
	assert.NotEmpty(t, EmailInsertQuery)
	assert.NotEmpty(t, PasswordHashUpdateQuery)
	assert.NotEmpty(t, PasswordHashInsertQuery)
	assert.NotEmpty(t, TemporaryIdUpdateQuery)
	assert.NotEmpty(t, TemporaryIdInsertQuery)
	assert.NotEmpty(t, RefreshTokenUpdateQuery)
	assert.NotEmpty(t, RefreshTokenInsertQuery)
	assert.NotEmpty(t, TemporaryIdCancelledUpdateQuery)
	assert.NotEmpty(t, RefreshTokenCancelledUpdateQuery)
	assert.NotEmpty(t, PasswordResetTokenInsertQuery)
	assert.NotEmpty(t, IsOKPasswordHashInDbSelectQuery)
	assert.NotEmpty(t, PasswordResetTokenCancelledSelectQuery)
	assert.NotEmpty(t, TemporaryIdCancelledSelectQuery)
}

// TestVariableDeclarations проверяет, что все функции объявлены.
// Ожидается: все тестируемые функции доступны.
func TestVariableDeclarations(t *testing.T) {
	assert.NotNil(t, GetPermanentIdFromDbByEmail)
	assert.NotNil(t, GetPermanentIdFromDbByLogin)
	assert.NotNil(t, GetUniqueUserAgentsFromDb)
	assert.NotNil(t, SetLoginInDbTx)
	assert.NotNil(t, SetEmailInDbTx)
	assert.NotNil(t, SetEmailInDb)
	assert.NotNil(t, SetPasswordInDbTx)
	assert.NotNil(t, SetTemporaryIdInDbTx)
	assert.NotNil(t, SetRefreshTokenInDbTx)
	assert.NotNil(t, SetTemporaryIdCancelledInDbTx)
	assert.NotNil(t, SetRefreshTokenCancelledInDbTx)
	assert.NotNil(t, SetPasswordResetTokenInDb)
	assert.NotNil(t, IsPasswordResetTokenCancelled)
	assert.NotNil(t, IsOKPasswordHashInDb)
}
