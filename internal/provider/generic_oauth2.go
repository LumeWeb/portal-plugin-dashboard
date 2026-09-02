package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/knadh/koanf/v2"
	"github.com/samber/lo"
	"golang.org/x/oauth2"
)

// mapProvider adapts a decoded userinfo map to koanf's Provider interface.
type mapProvider map[string]any

func (m mapProvider) Read() (map[string]any, error) { return m, nil }
func (mapProvider) ReadBytes() ([]byte, error) {
	return nil, fmt.Errorf("map provider only supports Read")
}

// GenericOAuth2Provider implements OAuthProvider using golang.org/x/oauth2
// with config-driven endpoints and user-info field mapping.
type GenericOAuth2Provider struct {
	name        string
	displayName string
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
		emailKey: lo.Ternary(emailKey != "", emailKey, "email"),
		idKey:    lo.Ternary(idKey != "", idKey, "id"),
		nameKey:  lo.Ternary(nameKey != "", nameKey, "name"),
	}
}

func (p *GenericOAuth2Provider) Name() string { return p.name }

func (p *GenericOAuth2Provider) DisplayName() string {
	if p.displayName != "" {
		return p.displayName
	}
	return p.name
}

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
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber() // keep numeric ids precise and typed, not float64
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	k := koanf.New(".")
	if err := k.Load(mapProvider(raw), nil); err != nil {
		return nil, fmt.Errorf("load userinfo: %w", err)
	}

	// A missing or empty identity/email must reject the exchange rather than
	// collapsing distinct users into a "<nil>" principal.
	id, idOK := valueAt(k, p.idKey)
	if !idOK || id == "" {
		return nil, fmt.Errorf("userinfo missing id key %q", p.idKey)
	}
	email, emailOK := valueAt(k, p.emailKey)
	if !emailOK || email == "" {
		return nil, fmt.Errorf("userinfo missing email key %q", p.emailKey)
	}

	// Name is optional; keep it empty when the provider omits it.
	var name string
	if n, ok := valueAt(k, p.nameKey); ok {
		name = n
	}

	user := &OAuth2User{
		ProviderUserID: id,
		Email:          email,
		Name:           name,
	}

	// Only an explicit JSON boolean true verifies the email. koanf's Bool
	// getter would coerce non-bool truthy values (string "true", numeric 1)
	// via toBool, widening the verification boundary so a provider emitting
	// non-standard types could auto-verify an email it never confirmed.
	if verified, ok := k.Get("email_verified").(bool); ok {
		user.EmailVerified = verified
	}

	return user, nil
}

// valueAt fetches a dot-notation key (e.g. "data.id") via koanf. Only scalar
// string/number values are accepted; absent keys or aggregate values (objects,
// arrays) report false so callers reject them instead of building a principal
// from a garbage-formatted value.
func valueAt(k *koanf.Koanf, key string) (string, bool) {
	if !k.Exists(key) {
		return "", false
	}
	switch v := k.Get(key).(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}
