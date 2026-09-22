package external

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
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
