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

func DBConn() error {
	password, err := os.ReadFile(DBPasswordPathStr)
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

	DB, err := sql.Open(DBNameDriverStr, cfg.FormatDSN())
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	err = DB.Ping()
	if err != nil {
		log.Printf(DBPingFailedErr, err)
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
		log.Fatal(DBStartFailedErr)
	}

	inputEmail := user.GetEmail()
	row := DB.QueryRow(SelectQuery, inputEmail)
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
		log.Fatal(DBStartFailedErr)
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

	_, err = DB.Exec(InsertQuery, email, login, hashedPassword)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	return nil
}
