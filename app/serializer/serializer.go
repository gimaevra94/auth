package serializer

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gorilla/sessions"
)

func SessionUserGetUnmarshal(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, structs.User, error) {

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		log.Println(consts.SessionGetFailedErr, err)
		return nil, nil, err
	}

	jsonData, ok := session.Values[consts.UserStr].([]byte)
	if !ok {
		log.Println(consts.UserNotExistInSessionErr)
		return nil, nil, err
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		log.Println(consts.UserDeserializeFailedErr, err)
		return nil, nil, err
	}

	return session, user, nil
}

func SessionUserSetMarshal(w http.ResponseWriter, r *http.Request,
	store *sessions.CookieStore, user structs.User) error {

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		log.Println(consts.SessionGetFailedErr, err)
		return err
	}
	jsonData, err := json.Marshal(user)
	if err != nil {
		log.Println(consts.UserSerializeFailedErr, err)
		return err
	}

	session.Values[consts.UserStr] = jsonData
	err = session.Save(r, w)
	if err != nil {
		log.Println(consts.UserSaveInSessionFailedErr, err)
		return err
	}
	return nil
}
