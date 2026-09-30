package external

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDropboxOfflineGrant(t *testing.T) {
	u, _ := url.Parse(AuthorizeProviderGrant("dropbox", "id", "state", "nonce", "verifier", "account", DropboxFilesScope))
	q := u.Query()
	if q.Get("scope") != DropboxFilesScope || q.Get("token_access_type") != "offline" || q.Get("code_challenge_method") != "S256" || q.Get("state") != "state" || q.Get("redirect_uri") != RedirectURI {
		t.Fatal(q)
	}
	for _, test := range []struct {
		name, scope, refresh string
		valid                bool
	}{
		{"all", DropboxFilesScope, "refresh", true},
		{"identity-only", "account_info.read", "refresh", false},
		{"online-only", DropboxFilesScope, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				var body []byte
				if r.URL.Path == "/oauth2/token" {
					r.ParseForm()
					if r.URL.Host != "api.dropboxapi.com" || r.Form.Get("code_verifier") != "verifier" {
						t.Fatal(r.URL, r.Form)
					}
					body, _ = json.Marshal(map[string]any{"access_token": "access", "token_type": "bearer", "refresh_token": test.refresh, "scope": test.scope, "expires_in": 14400})
				} else {
					body = []byte(`{"account_id":"dbid:123","email":"a@example.test","email_verified":true}`)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			auth, err := ExchangeDropboxGrant(context.Background(), client, "id", "secret", "code", "verifier", DropboxFilesScope)
			if (err == nil) != test.valid {
				t.Fatal(err)
			}
			if test.valid && (auth.Account.Subject != "dbid:123" || auth.Token.RefreshToken != "refresh") {
				t.Fatal("identity or offline credential missing")
			}
		})
	}
}

func TestDropboxRefreshUsesDropboxAndPreservesRefresh(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			r.ParseForm()
			if r.URL.String() != "https://api.dropboxapi.com/oauth2/token" || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh" {
				t.Fatal(r.URL, r.Form)
			}
			body, status := `{"access_token":"renewed","token_type":"bearer","expires_in":14400}`, 200
			if revoked {
				body, status = `{"error":"invalid_grant"}`, 400
			}
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		token, err := RefreshProvider(context.Background(), client, "dropbox", "id", "secret", &oauth2.Token{AccessToken: "old", TokenType: "Bearer", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Hour)})
		if revoked {
			if !errors.Is(err, ErrReconnect) {
				t.Fatal(err)
			}
		} else if err != nil || token.AccessToken != "renewed" || token.RefreshToken != "refresh" {
			t.Fatal(token, err)
		}
	}
}
