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
	name     string
	config   *oauth2.Config
	userURL  string
	emailKey string
	idKey    string
	nameKey  string
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

	if v, ok := raw["email_verified"]; ok {
		if b, ok := v.(bool); ok {
			user.EmailVerified = b
		}
	}

	return user, nil
}

// valueAt fetches a dot-notation key (e.g. "data.id") via koanf and reports
// whether it was present and non-nil, so callers never receive a
// "<nil>"-formatted value.
func valueAt(k *koanf.Koanf, key string) (string, bool) {
	if !k.Exists(key) {
		return "", false
	}
	v := k.Get(key)
	if v == nil {
		return "", false
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	return fmt.Sprintf("%v", v), true
}
