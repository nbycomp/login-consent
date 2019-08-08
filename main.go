package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/gorilla/schema"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/justinas/nosurf"
	"github.com/volatiletech/authboss"
	abclientstate "github.com/volatiletech/authboss-clientstate"
	abrenderer "github.com/volatiletech/authboss-renderer"
	_ "github.com/volatiletech/authboss/auth"
	"github.com/volatiletech/authboss/defaults"
	_ "github.com/volatiletech/authboss/register"
	"github.com/volatiletech/authboss/remember"
)

const (
	sessionCookieName = "nbycomp"
)

var (
	flagDebug    = true
	flagDebugDB  = true
	flagDebugCTX = true
)

type contextKey string

const (
	ctxKeyChallenge contextKey = "challenge"
	ctxKeyRemember  contextKey = "remember"
)

var (
	ab        = authboss.New()
	database  = NewMemStorer()
	schemaDec = schema.NewDecoder()

	sessionStore abclientstate.SessionStorer
	cookieStore  abclientstate.CookieStorer
)

func main() {
	cookieStore = abclientstate.NewCookieStorer(securecookie.GenerateRandomKey(64), nil)
	cookieStore.Secure = false
	sessionStore = abclientstate.NewSessionStorer(sessionCookieName, securecookie.GenerateRandomKey(64))

	cStore := sessionStore.Store.(*sessions.CookieStore)
	cStore.Options.Secure = false
	cStore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	// replace in-memory storage with something supporting
	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	// add templates to views directory to override ugly defaults
	ab.Config.Core.ViewRenderer = abrenderer.NewHTML("/auth", "ab_views")

	ab.Config.Modules.RegisterPreserveFields = []string{"email", "name"}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "3000"
	}

	ab.Config.Paths.RootURL = "http://localhost:" + port

	defaults.SetCore(&ab.Config, false, false)

	// Here we initialize the bodyreader as something customized in order to accept a name
	// parameter for our user as well as the standard e-mail and password.
	//
	// We also change the validation for these fields
	// to be something less secure so that we can use test data easier.
	emailRule := defaults.Rules{
		FieldName: "email", Required: true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]{1,}`),
	}
	passwordRule := defaults.Rules{
		FieldName: "password", Required: true,
		MinLength: 4,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		Rulesets: map[string][]defaults.Rules{
			"register":    {emailRule, passwordRule},
			"recover_end": {passwordRule},
		},
		Confirms: map[string][]string{
			"register":    {"password", authboss.ConfirmPrefix + "password"},
			"recover_end": {"password", authboss.ConfirmPrefix + "password"},
		},
		Whitelist: map[string][]string{
			"register": []string{"email", "password"},
		},
	}

	if err := ab.Init(); err != nil {
		panic(err)
	}

	schemaDec.IgnoreUnknownKeys(true)

	mux := chi.NewRouter()

	mux.Use(logger,
		nosurf.NewPure,
		ab.LoadClientStateMiddleware,
		remember.Middleware(ab),
	)

	mux.Group(func(mux chi.Router) {
		mux.Use(login)
		mux.Use(dataInjector, authboss.ModuleListMiddleware(ab))
		mux.Mount("/auth", http.StripPrefix("/auth", ab.Config.Core.Router))
	})

	mux.Group(func(mux chi.Router) {
		mux.Use(dataInjector, authboss.ModuleListMiddleware(ab))

		mux.Route("/consent", func(mux chi.Router) {
			c := &http.Client{
				Timeout: 10 * time.Second,
			}

			mux.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ch := r.URL.Query().Get("consent_challenge"); ch != "" {
					var getConsentRes struct {
						Skip                         bool     `json:"skip"`
						RequestedScope               []string `json:"requested_scope"`
						RequestedAccessTokenAudience []string `json:"requested_access_token_audience"`
					}

					getJSON(c, makeURL("/oauth2/auth/requests/consent", "consent", ch), &getConsentRes)

					var acceptConsentRes struct {
						RedirectTo string `json:"redirect_to"`
					}

					var name string
					if user, err := getUser(&r); err == nil {
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

					putJSON(c, makeURL("/oauth2/auth/requests/consent/accept", "consent", ch), body, &acceptConsentRes)

					http.Redirect(w, r, acceptConsentRes.RedirectTo, 302)
				}
			}))

		})
	})

	log.Printf("Listening on localhost: %s", port)
	log.Println(http.ListenAndServe("localhost:"+port, mux))
}

func dataInjector(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := layoutData(w, &r)
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		handler.ServeHTTP(w, r)
	})
}

// layoutData is passing pointers to pointers be able to edit the current pointer
// to the request. This is still safe as it still creates a new request and doesn't
// modify the old one, it just modifies what we're pointing to in our methods so
// we're able to skip returning an *http.Request everywhere
func layoutData(w http.ResponseWriter, r **http.Request) authboss.HTMLData {
	var loggedIn bool
	var currentUserName string

	if user, err := getUser(r); user != nil && err == nil {
		loggedIn = true
		currentUserName = user.Name
	}

	return authboss.HTMLData{
		"loggedin":          loggedIn,
		"current_user_name": currentUserName,
		"csrf_token":        nosurf.Token(*r),
		"challenge":         (*r).Context().Value(ctxKeyChallenge),
		"flash_success":     authboss.FlashSuccess(w, *r),
		"flash_error":       authboss.FlashError(w, *r),
	}
}

func getJSON(client *http.Client, url string, target interface{}) error {
	r, err := client.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

func putJSON(client *http.Client, url string, body interface{}, target interface{}) error {
	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonBody))

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func makeURL(path, flow, challenge string) string {
	u, err := url.Parse(os.Getenv("HYDRA_ADMIN_URL"))
	if err != nil {
		panic(err)
	}

	u.Path = path

	q := u.Query()
	q.Set(flow+"_challenge", challenge)
	u.RawQuery = q.Encode()

	return u.String()
}

func getUser(r **http.Request) (*User, error) {
	userInter, err := ab.LoadCurrentUser(r)
	if err != nil {
		return nil, err
	}

	return userInter.(*User), nil
}

func login(handler http.Handler) http.Handler {
	c := &http.Client{
		Timeout: 10 * time.Second,
	}

	acceptLoginRequest := func(challenge string, body map[string]interface{}) string {
		var acceptLoginRes struct {
			RedirectTo string `json:"redirect_to"`
		}

		putJSON(c, makeURL("/oauth2/auth/requests/login/accept", "login", challenge), body, &acceptLoginRes)

		return acceptLoginRes.RedirectTo
	}

	ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		user, err := getUser(&r)
		if err != nil {
			return false, err
		}

		remember := r.Context().Value(ctxKeyRemember).(bool)

		body := map[string]interface{}{
			"subject":  user.GetEmail(),
			"remember": remember,
		}

		ch := r.Context().Value(ctxKeyChallenge).(string)
		redirectURL := acceptLoginRequest(ch, body)

		ab.Paths.AuthLoginOK = redirectURL

		return false, nil
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
		fmt.Println(r.Method)
		if r.URL.Path == "/auth/login" && r.Method == "GET" {
			if ch := r.URL.Query().Get("login_challenge"); ch != "" {
				getLoginURL := makeURL("/oauth2/auth/requests/login", "login", ch)

				var getLoginRes struct {
					Skip    bool   `json:"skip"`
					Subject string `json:"subject"`
				}

				getJSON(c, getLoginURL, &getLoginRes)

				if getLoginRes.Skip {
					body := map[string]interface{}{
						"subject": getLoginRes.Subject,
					}
					redirectURL := acceptLoginRequest(ch, body)
					http.Redirect(w, r, redirectURL, http.StatusFound)
					return
				}

				r = r.WithContext(context.WithValue(r.Context(), ctxKeyChallenge, ch))
			}
		} else if r.URL.Path == "/auth/login" && r.Method == "POST" {
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyChallenge, r.FormValue("challenge")))

			var remember bool
			if s, err := strconv.ParseBool(r.FormValue("rm")); err != nil {
				remember = s
			}

			r = r.WithContext(context.WithValue(r.Context(), ctxKeyRemember, remember))
		}

		handler.ServeHTTP(w, r)
	})
}

func consent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})
}
