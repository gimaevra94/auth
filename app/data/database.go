package data

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const (
	userInsertQuery  = "insert into user (userId,login,email,passwordHash,temporaryUserID,permanentUserID,temporaryCancelled) values(?,?,?,?,?,?,?)"
	temporaryIDQuery = "update user set temporaryUserID where login = ?"
	tokenInsertQuery = "insert into token (userId,token,deviceInfo,tokenCancelled) values (?,?,?,?)"
	tokenSelectQuery = "select refreshToken from token where userID =? limit 1"
	yauthSelectQuery = "select email from user where email = ? limit 1"
	yauthInsertQuery = "insert into user (login,email) values(?,?)"
)

func DBConn() error {
	dbPassword := []byte(os.Getenv("DB_PASSWORD"))

	cfg := mysql.Config{
		User:   "root",
		Passwd: string(dbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
		DBName: "db",
	}

	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return errors.WithStack(err)
	}

	return nil
}

func query(s string) string {
	return fmt.Sprintf("select passwordHash, permanentUserID,temporaryCancelled from user where %s = ? limit 1", s)
}

func UserCheck(queryValue string, login, password string) error {
	row := db.QueryRow(query(queryValue), login)
	var passwordHash string
	var permanentUserID string
	err := row.Scan(&passwordHash, &permanentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(password))
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func TemporaryUserIDAdd(login, temporaryUserID string) error {
	_, err := db.Exec(temporaryIDQuery, temporaryUserID, login)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func UserAdd(login, email, password, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = db.Exec(userInsertQuery, login, email, hashedPassword, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func RefreshTokenCheck(userID string) (string, string, bool, error) {
	row := db.QueryRow(tokenSelectQuery, userID)
	var refreshToken string
	var deviceInfo string
	var cancelled bool
	err := row.Scan(&refreshToken, &cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, errors.WithStack(err)
		}
		return "", "", false, errors.WithStack(err)
	}
	return refreshToken, deviceInfo, cancelled, nil
}

func RefreshTokenAdd(permanentUserID, refreshToken, deviceInfo string, tokenCancelled bool) error {
	_, err := db.Exec(tokenInsertQuery, permanentUserID, refreshToken, deviceInfo, tokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

//func TokenCancel(jti string) error {
//	db.QueryRow()
//}

func YauthUserCheck(email string) error {
	row := db.QueryRow(yauthSelectQuery, email)
	var existingEmail string
	err := row.Scan(&existingEmail)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}

	return nil
}

func YauthUserAdd(login, email string) error {
	_, err := db.Exec(yauthInsertQuery, login, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func DBClose() {
	if db != nil {
		db.Close()
	}
}
