package external

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestGitHubRepositoryGrant(t *testing.T) {
	u, _ := url.Parse(AuthorizeProviderGrant("github", "id", "state", "nonce", "verifier", "123", GitHubRepoScope))
	if u.Query().Get("scope") != "read:user repo" || u.Query().Get("code_challenge") == "" || u.Query().Get("prompt") != "select_account" {
		t.Fatal(u)
	}
	for _, scope := range []string{"read:user,repo", "repo", "read:user", "public_repo"} {
		t.Run(scope, func(t *testing.T) {
			client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				body := `{"id":123,"login":"alice"}`
				if r.URL.Host == "github.com" {
					body = `{"access_token":"private-token","token_type":"bearer","scope":"` + scope + `"}`
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			auth, err := ExchangeGitHubGrant(context.Background(), client, "id", "secret", "code", "verifier", GitHubRepoScope)
			valid := scope == "repo" || scope == "read:user,repo"
			if valid != (err == nil) {
				t.Fatal(err)
			}
			if valid && (auth.Account.Subject != "123" || !auth.Token.Expiry.IsZero()) {
				t.Fatal(auth.Account)
			}
		})
	}
}

func TestGitHubNonExpiringToken(t *testing.T) {
	token := &oauth2.Token{AccessToken: "secret", TokenType: "bearer"}
	status := 200
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{"X-Oauth-Scopes": []string{"repo, read:user"}}, Body: io.NopCloser(strings.NewReader(`{"id":123}`))}, nil
	})}
	updated, err := RefreshProvider(context.Background(), client, "github", "id", "secret", token)
	if err != nil || updated != token || !updated.Expiry.IsZero() {
		t.Fatal("must preserve actual lifetime", err)
	}
	status = 401
	if _, err = RefreshProvider(context.Background(), client, "github", "id", "secret", token); err != ErrReconnect {
		t.Fatal("revoked token must invalidate reusable authorization", err)
	}
	expired := &oauth2.Token{AccessToken: "secret", TokenType: "bearer", Expiry: time.Now().Add(-time.Hour)}
	if _, err = RefreshProvider(context.Background(), http.DefaultClient, "github", "id", "secret", expired); err == nil {
		t.Fatal("expired token without refresh accepted")
	}
}
