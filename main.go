package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"os"
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
	_ "github.com/volatiletech/authboss/logout"
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
	cookieStore = abclientstate.NewCookieStorer(storeKey("COOKIE_STORE_KEY"), nil)
	cookieStore.Secure = false
	sessionStore = abclientstate.NewSessionStorer(sessionCookieName, storeKey("SESSION_STORE_KEY"), nil)

	cStore := sessionStore.Store.(*sessions.CookieStore)
	cStore.Options.Secure = false
	cStore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	if filename := os.Getenv("IMPORT_USERS"); filename != "" {
		log.Printf("Importing users from file: %s\n", filename)
		repo.Import(filename, database)
	}

	ab.Config.Paths.Mount = "/auth"
	ab.Config.Core.ViewRenderer = abrenderer.NewHTML(ab.Config.Paths.Mount, "ab_views")
	ab.Config.Modules.LogoutMethod = http.MethodGet
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

	if err := ab.Init(); err != nil {
		panic(err)
	}

	schemaDec.IgnoreUnknownKeys(true)

	mux := chi.NewRouter()

	mux.Use(logger,
		nosurf.NewPure,
		ab.LoadClientStateMiddleware,
		dataInjector,
		authboss.ModuleListMiddleware(ab),
	)

	mux.Route(ab.Config.Paths.Mount, func(mux chi.Router) {
		mws := chi.Chain(login.LoginMiddleware(ab), login.LogoutMiddleware(ab))
		mux.Mount("/", http.StripPrefix(ab.Config.Paths.Mount, mws.Handler(ab.Config.Core.Router)))
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

func storeKey(envKey string) []byte {
	key := os.Getenv(envKey)
	if key == "" {
		log.Printf("generating random 64 byte key (override by setting %s to a base64-encoded string)\n", envKey)
		return securecookie.GenerateRandomKey(64)
	}

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatalf("failed to base64-decode %s", envKey)
	} else if len(decoded) != 64 {
		log.Fatalf("%s is the incorrect length, should be 64 bytes", envKey)
	}

	return decoded
}
