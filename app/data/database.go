package data

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/errs"
	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

const (
	selectQuery      = "select passwordHash from user where email = ? limit 1"
	insertQuery      = "insert into user (email,login,passwordHash) values(?,?,?)"
	yauthSelectQuery = "select email from user where email = ? limit 1"
	yauthInsertQuery = "insert into user (email,login) values(?,?)"
)

func DBConn() error {
	dbPassword := []byte(os.Getenv("DB_PASSWORD"))
	if len(dbPassword) == 0 {
		newErr := errors.New(NotExistErr)
		wrappedErr := errors.Wrapf(newErr, "dbPassword")
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	defer func() {
		for i := range dbPassword {
			dbPassword[i] = 0
		}
	}()

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
		WithStackedErr := errors.WithStack(err)
		log.Printf("%+v", WithStackedErr)
		return WithStackedErr
	}

	err = DB.Ping()
	if err != nil {
		DB.Close()
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	return nil
}

func UserCheck(w http.ResponseWriter, r *http.Request, user User) error {
	if err := DB.Ping(); err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	row := DB.QueryRow(selectQuery, user.Email)
	var passwordHash string
	err := row.Scan(&passwordHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return errs.OrigErrWrapPrintRedir(w, r, "", err)
		}
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(user.Password))
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	return nil

}

func UserAdd(w http.ResponseWriter, r *http.Request, user User) error {
	if err := DB.Ping(); err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password),
		bcrypt.DefaultCost)
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	_, err = DB.Exec(insertQuery, user.Login, user.Email, hashedPassword)
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	return nil
}

func YauthUserCheck(w http.ResponseWriter, r *http.Request, user User) error {
	if err := DB.Ping(); err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	row := DB.QueryRow(yauthSelectQuery, user.Email)
	var existingEmail string
	err := row.Scan(&existingEmail)

	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewErrWrapPrintRedir(w, r, "", NotExistErr, "user")
		}
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	return nil
}

func YauthUserAdd(w http.ResponseWriter, r *http.Request, user User) error {
	_, err := DB.Exec(yauthInsertQuery, user.Login, user.Email)
	if err != nil {
		return errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	return nil
}
