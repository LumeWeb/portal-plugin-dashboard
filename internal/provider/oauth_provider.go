package provider

import "context"

// OAuth2User represents the user information retrieved from an OAuth2 provider.
type OAuth2User struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
}

// OAuthProvider is the interface for an OAuth2 client provider. The plugin
// implements this for each provider (or generically via config) and the API
// layer drives the redirect → exchange → userinfo flow.
type OAuthProvider interface {
	// AuthCodeURL builds the authorization redirect URL with PKCE S256.
	AuthCodeURL(state, codeChallenge string) string

	// Exchange trades the authorization code for user info. The codeVerifier
	// corresponds to the challenge presented in AuthCodeURL.
	Exchange(ctx context.Context, code, codeVerifier string) (*OAuth2User, error)

	// Name returns the provider identifier (e.g. "google").
	Name() string
}
