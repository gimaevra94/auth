package app

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

const (
	selectQuery = "select password from users where email = ? limit 1"
	insertQuery = "insert into users (email,login,password) values(?,?,?)"
)

const (
	dbStartFailedErr = "failed to start the database"
)

func DBConn() error {
	passwordFilePath := "/run/secrets/db_password"
	password, err := os.ReadFile(passwordFilePath)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)

		return wrappedErr
	}

	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	cfg := mysql.Config{
		User:   "root",
		Passwd: string(password),
		Net:    "tcp",
		Addr:   "db:3306",
		DBName: "db",
	}

	DB, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
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

func UserCheck(w http.ResponseWriter, r *http.Request,
	user User, userAddFromLogIn bool) error {

	if DB == nil {
		log.Fatal(dbStartFailedErr)
	}

	inputEmail := user.GetEmail()
	row := DB.QueryRow(selectQuery, inputEmail)
	var passwordHash string
	err := row.Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			newErr := errors.New(NotExistErr)
			wrappedErr := errors.Wrap(newErr, "user")
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	if userAddFromLogIn {
		inputPassword := user.GetPassword()
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
			[]byte(inputPassword))
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}
	}

	return nil
}

func UserAdd(w http.ResponseWriter, r *http.Request,
	users User) error {
	if DB == nil {
		log.Fatal(dbStartFailedErr)
	}

	email := users.GetEmail()
	login := users.GetLogin()
	password := users.GetPassword()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	_, err = DB.Exec(insertQuery, email, login, hashedPassword)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	return nil
}
