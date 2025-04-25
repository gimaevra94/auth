package database

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func DBConn() error {
	password, err := os.ReadFile(consts.DBPasswordPathStr)
	if err != nil {
		log.Println(consts.PasswordFileReadFailedErr, err)
		return err
	}

	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	cfg := mysql.Config{
		User:   consts.DBConfUserNameStr,
		Passwd: string(password),
		Net:    consts.DBConfNetNameStr,
		Addr:   consts.DBConfAddrNameStr,
		DBName: consts.DBConfDBNameStr,
	}

	DB, err := sql.Open(consts.DBNameDriverStr, cfg.FormatDSN())
	if err != nil {
		log.Println(consts.SqlOpenFailedErr, err)
		return err
	}

	err = DB.Ping()
	if err != nil {
		log.Println(consts.DBPingFailedErr, err)
		DB.Close()
		return err
	}

	return nil
}

func UserCheck(w http.ResponseWriter, r *http.Request,
	user structs.User, userAddFromLogIn bool) error {

	if DB == nil {
		log.Fatal(consts.DBStartFailedErr)
	}

	inputEmail := user.GetEmail()
	row := DB.QueryRow(consts.SelectQuery, inputEmail)
	var passwordHash string
	err := row.Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println(consts.UserNotExistInDBErr, err)
			return err
		}
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.DBQueryExecuteFailedErr, err)
		return err
	}

	if userAddFromLogIn {
		inputPassword := user.GetPassword()
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
			[]byte(inputPassword))
		if err != nil {
			http.ServeFile(w, r, consts.BadSignInHTML)
			log.Println(consts.PasswordsNotMatchErr, err)
			return err
		}
	}

	return nil
}

func UserAdd(w http.ResponseWriter, r *http.Request,
	users structs.User) error {
	if DB == nil {
		log.Fatal(consts.DBStartFailedErr)
	}

	email := users.GetEmail()
	login := users.GetLogin()
	password := users.GetPassword()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.PasswordHashingFailedErr)
		return err
	}

	_, err = DB.Exec(consts.InsertQuery, email, login, hashedPassword)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.UserAddInDBFailedErr)
		return err
	}

	return nil
}
