package external

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

const Gateway = "https://panasms-oauth-gateway.panasms.workers.dev"
const RedirectURI = Gateway + "/callback"

type Account struct {
	Subject string
	Email   string
	Name    string
}

func Config(clientID, secret string) *oauth2.Config {
	return &oauth2.Config{ClientID: clientID, ClientSecret: secret, RedirectURL: RedirectURI,
		Scopes:   []string{oidc.ScopeOpenID, "email", "profile"},
		Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", AuthStyle: oauth2.AuthStyleInParams}}
}
func Authorize(clientID, state, nonce, verifier string) string {
	return Config(clientID, "").AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "select_account"))
}
func Exchange(ctx context.Context, client *http.Client, clientID, secret, code, nonce, verifier string) (Account, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := Config(clientID, secret).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Account{}, errors.New("Google authorization failed")
	}
	return verifyAccount(ctx, token, clientID, nonce)
}
func verifyAccount(ctx context.Context, token *oauth2.Token, clientID, nonce string) (Account, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Account{}, errors.New("Google identity token missing")
	}
	keys := oidc.NewRemoteKeySet(ctx, "https://www.googleapis.com/oauth2/v3/certs")
	verified, err := oidc.NewVerifier("https://accounts.google.com", keys, &oidc.Config{ClientID: clientID}).Verify(ctx, raw)
	if err != nil || verified.Nonce != nonce {
		return Account{}, errors.New("Google identity validation failed")
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		Name     string `json:"name"`
	}
	if verified.Claims(&claims) != nil || !claims.Verified || claims.Email == "" || verified.Subject == "" {
		return Account{}, errors.New("Google account email is not verified")
	}
	return Account{Subject: verified.Subject, Email: claims.Email, Name: claims.Name}, nil
}

const DriveScope = "https://www.googleapis.com/auth/drive"
const DriveReadScope = "https://www.googleapis.com/auth/drive.readonly"

type Authorization struct {
	Account Account
	Token   *oauth2.Token
}

func AuthorizeGrant(clientID, state, nonce, verifier, subject, scope string) string {
	c := Config(clientID, "")
	c.Scopes = append(c.Scopes, scope)
	return c.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"), oauth2.SetAuthURLParam("login_hint", subject))
}
func ExchangeGrant(ctx context.Context, client *http.Client, clientID, secret, code, nonce, verifier, scope string) (Authorization, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	c := Config(clientID, secret)
	c.Scopes = append(c.Scopes, scope)
	token, err := c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Authorization{}, errors.New("Google grant exchange failed")
	}
	account, err := verifyAccount(ctx, token, clientID, nonce)
	if err != nil {
		return Authorization{}, err
	}
	granted, _ := token.Extra("scope").(string)
	found := false
	for _, value := range strings.Fields(granted) {
		if value == scope {
			found = true
		}
	}
	if !found || token.RefreshToken == "" || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || !token.Expiry.After(time.Now()) {
		return Authorization{}, errors.New("Google offline permission not granted")
	}
	return Authorization{Account: account, Token: token}, nil
}

var ErrReconnect = errors.New("external.reconnectRequired")

func Refresh(ctx context.Context, client *http.Client, clientID, secret string, token *oauth2.Token) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	updated, err := Config(clientID, secret).TokenSource(ctx, token).Token()
	if err != nil {
		var oauthErr *oauth2.RetrieveError
		if errors.As(err, &oauthErr) && oauthErr.ErrorCode == "invalid_grant" {
			return nil, ErrReconnect
		}
		return nil, errors.New("external.refreshUnavailable")
	}
	if updated.AccessToken == "" || !strings.EqualFold(updated.TokenType, "Bearer") || !updated.Expiry.After(time.Now()) {
		return nil, ErrReconnect
	}
	if updated.RefreshToken == "" {
		updated.RefreshToken = token.RefreshToken
	}
	return updated, nil
}
