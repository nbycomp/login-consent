package login

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/nbycomp/login/model"
	"github.com/volatiletech/authboss"
)

func Consent(ab *authboss.Authboss) http.Handler {
	mux := chi.NewRouter()

	mux.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ch := r.URL.Query().Get("consent_challenge"); ch != "" {
			var getConsentRes struct {
				Skip                         bool     `json:"skip"`
				RequestedScope               []string `json:"requested_scope"`
				RequestedAccessTokenAudience []string `json:"requested_access_token_audience"`
			}

			getJSON(makeURL("/oauth2/auth/requests/consent", "consent", ch), &getConsentRes)

			var acceptConsentRes struct {
				RedirectTo string `json:"redirect_to"`
			}

			var name string
			if user, err := model.GetUser(ab, &r); err == nil {
				name = user.Name
			}

			body := map[string]interface{}{
				"grant_scope":                 getConsentRes.RequestedScope,
				"grant_access_token_audience": getConsentRes.RequestedAccessTokenAudience,
				"session": map[string]interface{}{
					"access_token": struct{}{},
					"id_token": map[string]interface{}{
						"name": name,
					},
				},
			}

			putJSON(makeURL("/oauth2/auth/requests/consent/accept", "consent", ch), body, &acceptConsentRes)

			http.Redirect(w, r, acceptConsentRes.RedirectTo, http.StatusFound)
		}
	}))

	return mux
}
