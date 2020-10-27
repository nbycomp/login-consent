package login

import (
	"context"
	"net/http"

	"github.com/volatiletech/authboss"

	"github.com/nbycomp/login-consent/model"
)

type contextKey string

const (
	CTXKeyChallenge contextKey = "challenge"
)

type getLoginResponse struct {
	Skip    bool   `json:"skip"`
	Subject string `json:"subject"`
}

func getLoginRequest(challenge string) getLoginResponse {
	var res getLoginResponse
	url := makeGetURL(login, challenge)
	getJSON(url, &res)

	return res
}

type acceptLoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

func acceptLoginRequest(challenge string, body map[string]interface{}) acceptLoginResponse {
	var res acceptLoginResponse
	url := makeAcceptURL(login, challenge)
	putJSON(url, body, &res)

	return res
}

type Middleware func(http.Handler) http.Handler

func LoginMiddleware(ab *authboss.Authboss) Middleware {
	return func(handler http.Handler) http.Handler {
		ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			user, err := model.GetUser(ab, &r)
			if err != nil {
				return false, err
			}

			body := map[string]interface{}{
				"subject":      user.GetEmail(),
				"remember":     true,
				"remember_for": 3600,
			}

			ch := r.Context().Value(CTXKeyChallenge).(string)
			res := acceptLoginRequest(ch, body)

			http.Redirect(w, r, res.RedirectTo, http.StatusFound)

			return true, nil
		})

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" {
				switch r.Method {
				case http.MethodGet:
					if ch := r.URL.Query().Get("login_challenge"); ch != "" {
						res := getLoginRequest(ch)

						if res.Skip {
							body := map[string]interface{}{
								"subject": res.Subject,
							}
							res := acceptLoginRequest(ch, body)
							http.Redirect(w, r, res.RedirectTo, http.StatusFound)
							return
						}

						r = r.WithContext(context.WithValue(r.Context(), CTXKeyChallenge, ch))

						if d, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData); ok {
							r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, d.MergeKV("challenge", ch)))
						}

					}
				case http.MethodPost:
					r = r.WithContext(context.WithValue(r.Context(), CTXKeyChallenge, r.FormValue("challenge")))
				}
			}

			handler.ServeHTTP(w, r)
		})
	}
}
