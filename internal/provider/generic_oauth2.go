package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// GenericOAuth2Provider implements OAuthProvider using golang.org/x/oauth2
// with config-driven endpoints and user-info field mapping.
type GenericOAuth2Provider struct {
	name        string
	config      *oauth2.Config
	userURL     string
	emailKey    string
	idKey       string
	nameKey     string
}

// NewGenericOAuth2Provider creates a config-driven OAuth2 provider.
func NewGenericOAuth2Provider(
	name string,
	clientID, clientSecret string,
	scopes []string,
	authURL, tokenURL, userURL, callbackURL string,
	emailKey, idKey, nameKey string,
) *GenericOAuth2Provider {
	return &GenericOAuth2Provider{
		name: name,
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		userURL:  userURL,
		emailKey: defaultIfEmpty(emailKey, "email"),
		idKey:    defaultIfEmpty(idKey, "id"),
		nameKey:  defaultIfEmpty(nameKey, "name"),
	}
}

func (p *GenericOAuth2Provider) Name() string { return p.name }

func (p *GenericOAuth2Provider) AuthCodeURL(state, codeChallenge string) string {
	return p.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *GenericOAuth2Provider) Exchange(ctx context.Context, code, codeVerifier string) (*OAuth2User, error) {
	token, err := p.config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	client := p.config.Client(ctx, token)
	resp, err := client.Get(p.userURL)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	user := &OAuth2User{
		ProviderUserID: fmt.Sprintf("%v", getString(raw, p.idKey)),
		Email:          fmt.Sprintf("%v", getString(raw, p.emailKey)),
		Name:           fmt.Sprintf("%v", getString(raw, p.nameKey)),
	}

	if v, ok := raw["email_verified"]; ok {
		if b, ok := v.(bool); ok {
			user.EmailVerified = b
		}
	}

	return user, nil
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// getString navigates a nested JSON map using dot-notation (e.g. "data.id").
func getString(data map[string]any, key string) any {
	parts := strings.Split(key, ".")
	var current any = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]any:
			current = v[part]
		default:
			return ""
		}
	}

	return current
}
