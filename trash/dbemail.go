package db

import (
	"database/sql"
	"errors"
	"log"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
)

var ErrEmailNotFound = errors.New("email not found")

func isEmailExist(users *structs.EmailUsers, db *sql.DB) error {

	row := db.QueryRow(consts.MailSelectQuery, users.Email)
	var existingEmail string
	err := row.Scan(&existingEmail)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Println(err)
			return ErrEmailNotFound
		}

		log.Println("email existence checking error", err)
		return err
	}

	return nil
}

func emailAdd(users *structs.EmailUsers, db *sql.DB) error {
	_, err := db.Exec(consts.MailInsertQuery, users.Email)
	if err != nil {
		log.Println("email inserting error", err)
		return err
	}
	return nil
}

func EmailCheckAndAdd(users *structs.EmailUsers, db *sql.DB) error {
	err := isEmailExist(users, db)
	if err != nil {
		if err == ErrEmailNotFound {

			err = emailAdd(users, db)
			if err != nil {
				log.Println("email adding error", err)
				return err
			}
			return nil
		}

		log.Println("email existence checking error", err)
		return err
	}
	return nil
}