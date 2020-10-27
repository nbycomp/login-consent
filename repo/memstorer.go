package repo

import (
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/nbycomp/login-consent/model"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	aboauth "github.com/volatiletech/authboss/oauth2"
)

var (
	assertStorer = &MemStorer{}

	_ authboss.CreatingServerStorer    = assertStorer
	_ authboss.ConfirmingServerStorer  = assertStorer
	_ authboss.RecoveringServerStorer  = assertStorer
	_ authboss.RememberingServerStorer = assertStorer
)

// MemStorer stores users in memory
type MemStorer struct {
	Users  map[string]model.User
	Tokens map[string][]string
}

// NewMemStorer constructor
func NewMemStorer() *MemStorer {
	return &MemStorer{
		Users:  map[string]model.User{},
		Tokens: make(map[string][]string),
	}
}

// Save the user
func (m MemStorer) Save(ctx context.Context, user authboss.User) error {
	u := user.(*model.User)
	m.Users[u.Email] = *u

	fmt.Println("Saved user:", u.Name)
	return nil
}

// Load the user
func (m MemStorer) Load(ctx context.Context, key string) (user authboss.User, err error) {
	// Check to see if our key is actually an oauth2 pid
	provider, uid, err := authboss.ParseOAuth2PID(key)
	if err == nil {
		for _, u := range m.Users {
			if u.OAuth2Provider == provider && u.OAuth2UID == uid {
				fmt.Println("Loaded OAuth2 user:", u.Email)
				return &u, nil
			}
		}

		return nil, authboss.ErrUserNotFound
	}

	u, ok := m.Users[key]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	fmt.Println("Loaded user:", u.Name)
	return &u, nil
}

// New user creation
func (m MemStorer) New(ctx context.Context) authboss.User {
	return &model.User{}
}

// Create the user
func (m MemStorer) Create(ctx context.Context, user authboss.User) error {
	u := user.(*model.User)

	if _, ok := m.Users[u.Email]; ok {
		return authboss.ErrUserFound
	}

	fmt.Println("Created new user:", u.Name)
	m.Users[u.Email] = *u
	return nil
}

// LoadByConfirmSelector looks a user up by confirmation token
func (m MemStorer) LoadByConfirmSelector(ctx context.Context, selector string) (user authboss.ConfirmableUser, err error) {
	for _, v := range m.Users {
		if v.ConfirmSelector == selector {
			fmt.Println("Loaded user by confirm selector:", selector, v.Name)
			return &v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// LoadByRecoverSelector looks a user up by confirmation selector
func (m MemStorer) LoadByRecoverSelector(ctx context.Context, selector string) (user authboss.RecoverableUser, err error) {
	for _, v := range m.Users {
		if v.RecoverSelector == selector {
			fmt.Println("Loaded user by recover selector:", selector, v.Name)
			return &v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// AddRememberToken to a user
func (m MemStorer) AddRememberToken(ctx context.Context, pid, token string) error {
	m.Tokens[pid] = append(m.Tokens[pid], token)
	fmt.Printf("Adding rm token to %s: %s\n", pid, token)
	spew.Dump(m.Tokens)
	return nil
}

// DelRememberTokens removes all tokens for the given pid
func (m MemStorer) DelRememberTokens(ctx context.Context, pid string) error {
	delete(m.Tokens, pid)
	fmt.Println("Deleting rm tokens from:", pid)
	spew.Dump(m.Tokens)
	return nil
}

// UseRememberToken finds the pid-token pair and deletes it.
// If the token could not be found return ErrTokenNotFound
func (m MemStorer) UseRememberToken(ctx context.Context, pid, token string) error {
	tokens, ok := m.Tokens[pid]
	if !ok {
		fmt.Println("Failed to find rm tokens for:", pid)
		return authboss.ErrTokenNotFound
	}

	for i, tok := range tokens {
		if tok == token {
			tokens[len(tokens)-1] = tokens[i]
			m.Tokens[pid] = tokens[:len(tokens)-1]
			fmt.Printf("Used remember for %s: %s\n", pid, token)
			return nil
		}
	}

	return authboss.ErrTokenNotFound
}

// NewFromOAuth2 creates an oauth2 user (but not in the database, just a blank one to be saved later)
func (m MemStorer) NewFromOAuth2(ctx context.Context, provider string, details map[string]string) (authboss.OAuth2User, error) {
	switch provider {
	case "google":
		email := details[aboauth.OAuth2Email]

		var user *model.User
		if u, ok := m.Users[email]; ok {
			user = &u
		} else {
			user = &model.User{}
		}

		// Google OAuth2 doesn't allow us to fetch real name without more complicated API calls
		// in order to do this properly in your own app, look at replacing the authboss oauth2.GoogleUserDetails
		// method with something more thorough.
		user.Name = "Unknown"
		user.Email = details[aboauth.OAuth2Email]
		user.OAuth2UID = details[aboauth.OAuth2UID]
		user.Confirmed = true

		return user, nil
	}

	return nil, errors.Errorf("unknown provider %s", provider)
}

// SaveOAuth2 user
func (m MemStorer) SaveOAuth2(ctx context.Context, user authboss.OAuth2User) error {
	u := user.(*model.User)
	m.Users[u.Email] = *u

	return nil
}

/*
func (s MemStorer) PutOAuth(uid, provider string, attr authboss.Attributes) error {
	return s.Create(uid+provider, attr)
}

func (s MemStorer) GetOAuth(uid, provider string) (result interface{}, err error) {
	user, ok := s.Users[uid+provider]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}

	return &user, nil
}

func (s MemStorer) AddToken(key, token string) error {
	s.Tokens[key] = append(s.Tokens[key], token)
	fmt.Println("AddToken")
	spew.Dump(s.Tokens)
	return nil
}

func (s MemStorer) DelTokens(key string) error {
	delete(s.Tokens, key)
	fmt.Println("DelTokens")
	spew.Dump(s.Tokens)
	return nil
}

func (s MemStorer) UseToken(givenKey, token string) error {
	toks, ok := s.Tokens[givenKey]
	if !ok {
		return authboss.ErrTokenNotFound
	}

	for i, tok := range toks {
		if tok == token {
			toks[i], toks[len(toks)-1] = toks[len(toks)-1], toks[i]
			s.Tokens[givenKey] = toks[:len(toks)-1]
			return nil
		}
	}

	return authboss.ErrTokenNotFound
}

func (s MemStorer) ConfirmUser(tok string) (result interface{}, err error) {
	fmt.Println("==============", tok)

	for _, u := range s.Users {
		if u.ConfirmToken == tok {
			return &u, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

func (s MemStorer) RecoverUser(rec string) (result interface{}, err error) {
	for _, u := range s.Users {
		if u.RecoverToken == rec {
			return &u, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}
*/
