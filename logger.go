package main

import (
	"fmt"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/volatiletech/authboss"
)

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n%s %s %s\n", r.Method, r.URL.Path, r.Proto)

		if flagDebug {
			session, err := sessionStore.Get(r, sessionCookieName)
			if err == nil {
				fmt.Print("Session: ")
				first := true
				for k, v := range session.Values {
					if first {
						first = false
					} else {
						fmt.Print(", ")
					}
					fmt.Printf("%s = %v", k, v)
				}
				fmt.Println()
			}
		}

		if flagDebugDB {
			fmt.Println("Database:")
			for _, u := range database.Users {
				fmt.Printf("! %#v\n", u)
			}
		}

		if flagDebugCTX {
			if val := r.Context().Value(authboss.CTXKeyData); val != nil {
				fmt.Printf("CTX Data: %s", spew.Sdump(val))
			}
			if val := r.Context().Value(authboss.CTXKeyValues); val != nil {
				fmt.Printf("CTX Values: %s", spew.Sdump(val))
			}
		}

		h.ServeHTTP(w, r)
	})
}
