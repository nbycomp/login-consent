package repo

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/volatiletech/authboss"
)

type ImportedUser struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// Import parses users from a JSON file and inserts them into the DB
func Import(filename string, db authboss.CreatingServerStorer) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("failed to import users from file %s\n", filename)
	}
	defer f.Close()

	var users []ImportedUser
	d := json.NewDecoder(f)
	err = d.Decode(&users)
	if err != nil {
		log.Fatalf("failed to parse users: %v\n", err)
	}

	for _, u := range users {
		user := authboss.MustBeAuthable(db.New(context.Background()))

		user.PutPID(u.Email)
		user.PutPassword(u.Password)

		if arbUser, ok := user.(authboss.ArbitraryUser); ok {
			arbUser.PutArbitrary(map[string]string{
				"name": u.Name,
				"role": u.Role,
			})
		}

		db.Create(context.Background(), user)
	}
}
