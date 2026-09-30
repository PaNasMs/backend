package external

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

func Supported(provider string) bool {
	return provider == "google" || provider == "github" || provider == "dropbox"
}
func LoginSupported(provider string) bool { return provider == "google" || provider == "github" }

var clientPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func ValidClient(provider, id string) bool {
	return Supported(provider) && len(id) > 0 && len(id) <= 256 && clientPattern.MatchString(id) && (provider != "google" || strings.HasSuffix(id, ".apps.googleusercontent.com"))
}

func providerConfig(provider, id, secret string) *oauth2.Config {
	c := &oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: RedirectURI}
	switch provider {
	case "github":
		c.Scopes = []string{"read:user"}
		c.Endpoint = oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams}
	case "dropbox":
		c.Scopes = []string{"account_info.read"}
		c.Endpoint = oauth2.Endpoint{AuthURL: "https://www.dropbox.com/oauth2/authorize", TokenURL: "https://api.dropboxapi.com/oauth2/token", AuthStyle: oauth2.AuthStyleInParams}
	}
	return c
}

func AuthorizeProvider(provider, id, state, nonce, verifier string) string {
	if provider == "google" {
		return Authorize(id, state, nonce, verifier)
	}
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if provider == "github" {
		options = append(options, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	if provider == "dropbox" {
		options = append(options, oauth2.SetAuthURLParam("force_reauthentication", "true"), oauth2.SetAuthURLParam("token_access_type", "online"))
	}
	return providerConfig(provider, id, "").AuthCodeURL(state, options...)
}

func ExchangeProvider(ctx context.Context, client *http.Client, provider, id, secret, code, nonce, verifier string) (Account, error) {
	if provider == "google" {
		return Exchange(ctx, client, id, secret, code, nonce, verifier)
	}
	if !Supported(provider) {
		return Account{}, errors.New("unsupported provider")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := providerConfig(provider, id, secret).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return Account{}, errors.New("provider authorization failed")
	}
	method, endpoint := http.MethodGet, "https://api.github.com/user"
	if provider == "dropbox" {
		method, endpoint = http.MethodPost, "https://api.dropboxapi.com/2/users/get_current_account"
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return Account{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PaNasMs")
	response, err := client.Do(req)
	if err != nil {
		return Account{}, errors.New("provider identity unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Account{}, errors.New("provider identity unavailable")
	}
	var result struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Email     string `json:"email"`
		AccountID string `json:"account_id"`
		Verified  bool   `json:"email_verified"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil {
		return Account{}, errors.New("invalid provider identity")
	}
	if provider == "github" && result.ID > 0 && result.Login != "" {
		return Account{Subject: strconv.FormatInt(result.ID, 10), Email: result.Email, Name: "@" + result.Login}, nil
	}
	if provider == "dropbox" && result.AccountID != "" && result.Verified && result.Email != "" {
		return Account{Subject: result.AccountID, Email: result.Email, Name: result.Email}, nil
	}
	return Account{}, errors.New("invalid provider identity")
}
