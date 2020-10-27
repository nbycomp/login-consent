package login

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/nbycomp/login-consent/model"
	"github.com/volatiletech/authboss"
)

type getConsentResponse struct {
	Skip                         bool     `json:"skip"`
	RequestedScope               []string `json:"requested_scope"`
	RequestedAccessTokenAudience []string `json:"requested_access_token_audience"`
}

func getConsentRequest(challenge string) getConsentResponse {
	var res getConsentResponse
	url := makeGetURL(consent, challenge)
	getJSON(url, &res)

	return res
}

type acceptConsentResponse struct {
	RedirectTo string `json:"redirect_to"`
}

func acceptConsentRequest(challenge string, body map[string]interface{}) acceptConsentResponse {
	var res acceptConsentResponse
	url := makeAcceptURL(consent, challenge)
	putJSON(url, body, &res)

	return res
}

type AccessToken struct {
	Role string `json:"role"`
}

type IDToken struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func Consent(ab *authboss.Authboss) http.Handler {
	mux := chi.NewRouter()

	mux.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ch := r.URL.Query().Get("consent_challenge"); ch != "" {
			getRes := getConsentRequest(ch)

			var accessToken AccessToken
			var idToken IDToken
			if user, err := model.GetUser(ab, &r); err == nil {
				accessToken = AccessToken{
					Role: user.Role,
				}
				idToken = IDToken{
					Name:  user.Name,
					Email: user.Email,
					Role:  user.Role,
				}
			}

			body := map[string]interface{}{
				"grant_scope":                 getRes.RequestedScope,
				"grant_access_token_audience": getRes.RequestedAccessTokenAudience,
				"session": map[string]interface{}{
					"access_token": accessToken,
					"id_token":     idToken,
				},
			}

			accRes := acceptConsentRequest(ch, body)

			http.Redirect(w, r, accRes.RedirectTo, http.StatusFound)
		}
	}))

	return mux
}
