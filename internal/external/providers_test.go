package external

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestProviderScopesAndPKCE(t *testing.T) {
	for provider, scope := range map[string]string{"github": "read:user", "dropbox": "account_info.read"} {
		u, _ := url.Parse(AuthorizeProvider(provider, "id", "state", "nonce", "verifier"))
		q := u.Query()
		if q.Get("scope") != scope || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") != "state" || q.Get("redirect_uri") != RedirectURI {
			t.Fatal(provider, q)
		}
	}
	if LoginSupported("dropbox") || !LoginSupported("github") || Supported("unknown") {
		t.Fatal("provider capabilities")
	}
}

func TestProviderVerifiedIdentity(t *testing.T) {
	for _, test := range []struct {
		provider, body, subject string
		valid                   bool
	}{
		{"github", `{"id":123,"login":"alice","email":null}`, "123", true},
		{"github", `{"login":"alice","email":"a@example.test"}`, "", false},
		{"dropbox", `{"account_id":"dbid:123","email":"a@example.test","email_verified":true,"name":{"display_name":"Alice"}}`, "dbid:123", true},
		{"dropbox", `{"account_id":"dbid:123","email":"a@example.test","email_verified":false}`, "", false},
		{"dropbox", `{"email":"a@example.test","email_verified":true}`, "", false},
	} {
		t.Run(test.provider+test.subject+test.body, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				calls++
				body := test.body
				if calls == 1 {
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Form.Get("code_verifier") != "verifier" || r.Form.Get("client_secret") != "secret" || r.Form.Get("redirect_uri") != RedirectURI {
						t.Fatal("missing exchange binding")
					}
					body = `{"access_token":"secret-token","token_type":"bearer"}`
				} else {
					if r.Header.Get("Authorization") != "Bearer secret-token" {
						t.Fatal("missing authentication")
					}
					if test.provider == "github" && (r.URL.String() != "https://api.github.com/user" || r.Method != "GET") {
						t.Fatal(r.URL, r.Method)
					}
					if test.provider == "dropbox" && (r.URL.String() != "https://api.dropboxapi.com/2/users/get_current_account" || r.Method != "POST") {
						t.Fatal(r.URL, r.Method)
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			account, err := ExchangeProvider(context.Background(), client, test.provider, "id", "secret", "code", "nonce", "verifier")
			if (err == nil) != test.valid || account.Subject != test.subject {
				t.Fatal(account, err)
			}
			if calls != 2 {
				t.Fatal(calls)
			}
		})
	}
}
