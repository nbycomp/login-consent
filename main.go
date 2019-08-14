package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/go-chi/chi"
	"github.com/gorilla/schema"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/justinas/nosurf"
	"github.com/nbycomp/login/login"
	"github.com/nbycomp/login/model"
	"github.com/nbycomp/login/repo"
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
	flagDebug    = false
	flagDebugDB  = false
	flagDebugCTX = false
)

var (
	ab        = authboss.New()
	database  = repo.NewMemStorer()
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

	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	ab.Config.Paths.Mount = "/auth"
	ab.Config.Core.ViewRenderer = abrenderer.NewHTML(ab.Config.Paths.Mount, "ab_views")

	ab.Config.Modules.RegisterPreserveFields = []string{"email", "name"}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "3000"
	}

	rootURL := os.Getenv("ROOT_URL")
	if rootURL == "" {
		rootURL = "http://localhost:" + port
	}
	_, err := url.Parse(rootURL)
	if err != nil {
		panic("invalid root URL passed")
	}
	ab.Config.Paths.RootURL = rootURL

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
		dataInjector,
		authboss.ModuleListMiddleware(ab),
	)

	mux.Route(ab.Config.Paths.Mount, func(mux chi.Router) {
		mux.Mount("/", http.StripPrefix("/auth", login.LoginMiddleware(ab)(ab.Config.Core.Router)))
		mux.Mount("/consent", login.Consent(ab))

		fs := http.FileServer(http.Dir("static"))
		mux.Mount("/static/", http.StripPrefix(ab.Config.Paths.Mount+"/static/", fs))
	})

	log.Printf("Listening on port %s", port)
	log.Println(http.ListenAndServe(":"+port, mux))
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

	if user, err := model.GetUser(ab, r); user != nil && err == nil {
		loggedIn = true
		currentUserName = user.Name
	}

	return authboss.HTMLData{
		"loggedin":          loggedIn,
		"current_user_name": currentUserName,
		"csrf_token":        nosurf.Token(*r),
		"flash_success":     authboss.FlashSuccess(w, *r),
		"flash_error":       authboss.FlashError(w, *r),
	}
}
