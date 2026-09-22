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

func TestGoogleGrantRequiresOfflineScopeAndVerifiedIdentity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "grant-key"))
	claims, _ := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "sub": "subject", "nonce": "nonce", "email": "test@example.test", "email_verified": true})
	signed, _ := signer.Sign(claims)
	jwt, _ := signed.CompactSerialize()
	for _, variant := range []string{"valid", "scope", "refresh", "expiry", "nonce"} {
		t.Run(variant, func(t *testing.T) {
			c := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				var body any
				if r.URL.Host == "oauth2.googleapis.com" {
					data := map[string]any{"access_token": "access", "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 3600, "id_token": jwt, "scope": "openid email profile " + DriveScope}
					if variant == "scope" {
						data["scope"] = "openid email profile"
					}
					if variant == "refresh" {
						delete(data, "refresh_token")
					}
					if variant == "expiry" {
						delete(data, "expires_in")
					}
					body = data
				} else {
					body = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "grant-key", Algorithm: "RS256", Use: "sig"}}}
				}
				raw, _ := json.Marshal(body)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}
			nonce := "nonce"
			if variant == "nonce" {
				nonce = "wrong"
			}
			grant, err := ExchangeGrant(context.Background(), c, "client", "secret", "code", nonce, "verifier", DriveScope)
			if variant == "valid" {
				if err != nil || grant.Account.Subject != "subject" || grant.Token.RefreshToken != "refresh" {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("incomplete consent accepted")
			}
		})
	}
	u, _ := url.Parse(AuthorizeGrant("client", "state", "nonce", "verifier", "subject", DriveReadScope))
	q := u.Query()
	if q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || q.Get("login_hint") != "subject" || q.Get("code_challenge_method") != "S256" || !strings.Contains(q.Get("scope"), DriveReadScope) {
		t.Fatal("unsafe grant authorize URL")
	}
}
