package external

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGoogleAuthorizationUsesPKCEAndMinimalScopes(t *testing.T) {
	u, err := url.Parse(Authorize("client", "state", "nonce", "verifier"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("scope") != "openid email profile" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "verifier" || q.Get("nonce") != "nonce" || q.Get("redirect_uri") != RedirectURI || q.Get("state") != "state" {
		t.Fatal(q)
	}
}
func TestGoogleIdentityValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"valid", "nonce", "aud", "iss", "expired", "email", "signature"} {
		t.Run(variant, func(t *testing.T) {
			claims := map[string]any{"iss": "https://accounts.google.com", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "sub": "account-id", "nonce": "nonce", "email": "user@example.test", "email_verified": true, "name": "Test User"}
			switch variant {
			case "nonce", "aud", "iss":
				claims[variant] = "wrong"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "email":
				claims["email_verified"] = false
			}
			raw, _ := json.Marshal(claims)
			signed, _ := signer.Sign(raw)
			jwt, _ := signed.CompactSerialize()
			if variant == "signature" {
				parts := strings.Split(jwt, ".")
				parts[2] = "invalid"
				jwt = strings.Join(parts, ".")
			}
			client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				var body []byte
				switch r.URL.Host {
				case "oauth2.googleapis.com":
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Form.Get("client_secret") != "secret" || r.Form.Get("code_verifier") != "verifier" || r.Form.Get("redirect_uri") != RedirectURI {
						t.Fatal(r.Form)
					}
					body, _ = json.Marshal(map[string]any{"access_token": "unused", "token_type": "Bearer", "id_token": jwt})
				case "www.googleapis.com":
					body, _ = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Algorithm: "RS256", Use: "sig"}}})
				default:
					t.Fatalf("unexpected host %s", r.URL.Host)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			account, err := Exchange(context.Background(), client, "client", "secret", "code", "nonce", "verifier")
			if variant == "valid" {
				if err != nil || account.Subject != "account-id" {
					t.Fatal(account, err)
				}
			} else if err == nil {
				t.Fatal("invalid identity accepted", variant)
			}
		})
	}
}
