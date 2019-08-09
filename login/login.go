package login

import (
	"context"
	"net/http"
	"strconv"

	"github.com/nbycomp/login/model"
	"github.com/volatiletech/authboss"
)

type contextKey string

const (
	CTXKeyChallenge contextKey = "challenge"
	CTXKeyRemember  contextKey = "remember"
)

type getLoginResponse struct {
	Skip    bool   `json:"skip"`
	Subject string `json:"subject"`
}

func getLoginRequest(challenge string) getLoginResponse {
	var res getLoginResponse
	url := makeURL("/oauth2/auth/requests/login", "login", challenge)
	getJSON(url, &res)

	return res
}

type acceptLoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

func acceptLoginRequest(challenge string, body map[string]interface{}) acceptLoginResponse {
	var res acceptLoginResponse
	url := makeURL("/oauth2/auth/requests/login/accept", "login", challenge)
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

			remember := r.Context().Value(CTXKeyRemember).(bool)

			body := map[string]interface{}{
				"subject":  user.GetEmail(),
				"remember": remember,
			}

			ch := r.Context().Value(CTXKeyChallenge).(string)
			res := acceptLoginRequest(ch, body)

			http.Redirect(w, r, res.RedirectTo, http.StatusFound)

			return true, nil
		})

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" {
				switch r.Method {
				case "GET":
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
				case "POST":
					r = r.WithContext(context.WithValue(r.Context(), CTXKeyChallenge, r.FormValue("challenge")))

					var remember bool
					if s, err := strconv.ParseBool(r.FormValue("rm")); err != nil {
						remember = s
					}

					r = r.WithContext(context.WithValue(r.Context(), CTXKeyRemember, remember))
				}
			}

			handler.ServeHTTP(w, r)
		})
	}
}
