package external

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const DropboxFilesScope = "account_info.read files.metadata.read files.content.read files.content.write"

func AuthorizeProviderGrant(provider, clientID, state, nonce, verifier, subject, scope string) string {
	if provider == "google" {
		return AuthorizeGrant(clientID, state, nonce, verifier, subject, scope)
	}
	if provider != "dropbox" || scope != DropboxFilesScope {
		return ""
	}
	c := providerConfig(provider, clientID, "")
	c.Scopes = strings.Fields(scope)
	return c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("token_access_type", "offline"), oauth2.SetAuthURLParam("force_reapprove", "true"))
}

func ExchangeDropboxGrant(ctx context.Context, client *http.Client, clientID, secret, code, verifier, scope string) (Authorization, error) {
	if scope != DropboxFilesScope {
		return Authorization{}, errors.New("unsupported Dropbox permission")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	c := providerConfig("dropbox", clientID, secret)
	c.Scopes = strings.Fields(scope)
	token, err := c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Authorization{}, errors.New("Dropbox grant exchange failed")
	}
	granted, _ := token.Extra("scope").(string)
	scopes := map[string]bool{}
	for _, value := range strings.Fields(granted) {
		scopes[value] = true
	}
	for _, value := range c.Scopes {
		if !scopes[value] {
			return Authorization{}, errors.New("Dropbox file permission not granted")
		}
	}
	if token.AccessToken == "" || token.RefreshToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || !token.Expiry.After(time.Now()) {
		return Authorization{}, errors.New("Dropbox offline permission not granted")
	}
	account, err := providerAccount(ctx, client, "dropbox", token)
	if err != nil {
		return Authorization{}, err
	}
	return Authorization{Account: account, Token: token}, nil
}
