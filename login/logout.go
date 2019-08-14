package login

import (
	"net/http"

	"github.com/volatiletech/authboss"
)

type getLogoutResponse struct {
}

func getLogoutRequest(challenge string) getLogoutResponse {
	var res getLogoutResponse
	url := makeGetURL(logout, challenge)
	getJSON(url, &res)

	return res
}

type acceptLogoutResponse struct {
	RedirectTo string `json:"redirect_to"`
}

func acceptLogoutRequest(challenge string) acceptLogoutResponse {
	var res acceptLogoutResponse
	url := makeAcceptURL(logout, challenge)
	putJSON(url, nil, &res)

	return res
}

func LogoutMiddleware(ab *authboss.Authboss) Middleware {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/logout" && r.Method == http.MethodGet {
				if ch := r.URL.Query().Get("logout_challenge"); ch != "" {
					getLogoutRequest(ch)
					res := acceptLogoutRequest(ch)
					ab.Paths.LogoutOK = res.RedirectTo
				}
			}

			handler.ServeHTTP(w, r)
		})
	}
}
