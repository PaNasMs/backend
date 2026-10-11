package external

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const GitHubRepoScope = "repo"

func validateGitHubToken(ctx context.Context, client *http.Client, token *oauth2.Token) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	res, err := client.Do(req)
	if err != nil {
		return errors.New("external.refreshUnavailable")
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode == http.StatusUnauthorized {
		return ErrReconnect
	}
	if res.StatusCode != http.StatusOK {
		return errors.New("external.refreshUnavailable")
	}
	if scopes := res.Header.Get("X-OAuth-Scopes"); scopes != "" {
		for _, scope := range strings.Split(scopes, ",") {
			if strings.TrimSpace(scope) == GitHubRepoScope {
				return nil
			}
		}
		return ErrReconnect
	}
	return nil
}

func ExchangeGitHubGrant(ctx context.Context, client *http.Client, clientID, secret, code, verifier, scope string) (Authorization, error) {
	if scope != GitHubRepoScope {
		return Authorization{}, errors.New("unsupported GitHub permission")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	c := providerConfig("github", clientID, secret)
	c.Scopes = []string{"read:user", GitHubRepoScope}
	token, err := c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Authorization{}, errors.New("GitHub grant exchange failed")
	}
	granted, _ := token.Extra("scope").(string)
	found := false
	for _, s := range strings.Fields(strings.ReplaceAll(granted, ",", " ")) {
		found = found || s == GitHubRepoScope
	}
	if !found || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || (!token.Expiry.IsZero() && !token.Expiry.After(time.Now())) {
		return Authorization{}, errors.New("GitHub repository permission not granted")
	}
	account, err := providerAccount(ctx, client, "github", token)
	if err != nil {
		return Authorization{}, err
	}
	return Authorization{Account: account, Token: token}, nil
}
