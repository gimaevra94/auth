package database

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEmailAdd(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open mock sql db: %s", err)
	}
	defer db.Close()

	users := Users{Email: "test@example.com"}

	mock.ExpectQuery("SELECT \\* FROM users WHERE email = \\? LIMIT 1").
		WithArgs(users.Email).
		WillReturnRows(sqlmock.NewRows([]string{"email"}))

	mock.ExpectExec("INSERT INTO users \\(email\\) VALUES \\(\\?\\)").
		WithArgs(users.Email).
		WillReturnResult(sqlmock.NewResult(1, 1))

	EmailAdd(users, db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %s", err)
	}

	mock.ExpectQuery("SELECT \\* FROM users WHERE email = \\? LIMIT 1").
		WithArgs(users.Email).
		WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow(users.Email))

	EmailAdd(users, db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %s", err)
	}
}
