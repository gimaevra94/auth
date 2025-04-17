package serializer

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/structs"
)

func Serialize(w http.ResponseWriter, r *http.Request,
	data structs.Users, value bool) (*structs.Users, error) {
	session, err := auth.Store.Get(r, "auth")
	if err != nil {
		log.Println("Failed to get the 'auth' session")
		return nil, err
	}

	if value {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Println("Failed to serialize the jsonData")
			return nil, err
		}

		session.Values["users"] = jsonData
		err = session.Save(r, w)
		if err != nil {
			log.Println("Failed to save the jsonData in the session")
			return nil, err
		}
	}

	jsonData, ok := session.Values["users"].(string)
	if !ok {
		log.Println("users not found in session")
		return nil, err
	}

	var users structs.Users
	err = json.Unmarshal([]byte(jsonData), &users)
	if err != nil {
		log.Println("users deserialization failed")
		return nil, err
	}

	return &users, nil
}

func SerializeAndSaveInSession(w http.ResponseWriter, r *http.Request,
	data structs.Users) error {

		

return nil
}
