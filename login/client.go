package login

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type flow string

const (
	login   flow = "login"
	consent flow = "consent"
	logout  flow = "logout"
)

var baseURL *url.URL
var client *http.Client

func init() {
	u, err := url.Parse(os.Getenv("HYDRA_ADMIN_URL"))
	if err != nil {
		panic(err)
	}

	baseURL = u

	client = &http.Client{
		Timeout: 10 * time.Second,
	}
}

func makeGetURL(f flow, challenge string) string {
	return makeURL("/oauth2/auth/requests/"+string(f), f, challenge)
}

func makeAcceptURL(f flow, challenge string) string {
	return makeURL("/oauth2/auth/requests/"+string(f)+"/accept", f, challenge)
}

func makeURL(path string, f flow, challenge string) string {
	p, err := url.Parse(path)
	if err != nil {
		panic(err)
	}

	u := baseURL.ResolveReference(p)

	q := u.Query()
	q.Set(string(f)+"_challenge", challenge)
	u.RawQuery = q.Encode()

	return u.String()
}

func getJSON(url string, target interface{}) error {
	res, err := client.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func putJSON(url string, body interface{}, target interface{}) error {
	var b io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		b = bytes.NewBuffer(jsonBody)
	}
	req, _ := http.NewRequest(http.MethodPut, url, b)

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}
