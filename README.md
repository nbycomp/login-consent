# Login/consent app

An application implementing the Login and Consent endpoints required by the OAuth2 Authorization Code flow.

Authentication is provided by [Authboss](https://github.com/volatiletech/authboss).

The code is based on the [reference implementation](https://github.com/ory/hydra-login-consent-node) for User Login and Consent flow, and the [authboss sample](https://github.com/volatiletech/authboss-sample).

The user is not prompted to provide consent; it is automatically granted, as this application is designed for first-party clients.

## Demo with ORY Hydra

```sh
hydra=oryd/hydra:v1.0.0
docker pull $hydra
```

Start hydra server:

```sh
docker run -it --rm --name login-consent-hydra -p 4444:4444 -p 4445:4445 \
    -e OAUTH2_SHARE_ERROR_DEBUG=1 \
    -e LOG_LEVEL=debug \
    -e OAUTH2_CONSENT_URL=http://localhost:3000/consent \
    -e OAUTH2_LOGIN_URL=http://localhost:3000/auth/login \
    -e OAUTH2_ISSUER_URL=http://localhost:4444 \
    -e DATABASE_URL=memory \
    $hydra serve all --dangerous-force-http

```

Register client app `test-client`:

```sh
docker run --link login-consent-hydra:hydra $hydra clients create \
    --endpoint http://hydra:4445 \
    --id test-client \
    --secret test-secret \
    --response-types code,id_token \
    --grant-types refresh_token,authorization_code \
    --scope openid,offline \
    --callbacks http://127.0.0.1:4446/callback
```

Run this application:
```sh
HYDRA_ADMIN_URL="http://localhost:4445" PORT=3000 go run .
```

Use Hydra's built in test client `hydra token user` to start the Authorization Code flow:

```sh
docker run -p 4446:4446 --link login-consent-hydra:hydra $hydra token user \
    --token-url http://hydra:4444/oauth2/token \
    --auth-url http://localhost:4444/oauth2/auth \
    --scope openid,offline \
    --client-id test-client \
    --client-secret test-secret
```

Visit http://localhost:4446 to start the process. Login using the credentials:

```
User: rick@councilofricks.com
Pass: 1234
```
