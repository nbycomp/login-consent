package login

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
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

func getJSON(url string, target interface{}) error {
	res, err := client.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func putJSON(url string, body interface{}, target interface{}) error {
	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonBody))

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}
