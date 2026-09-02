package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// fakeCookieSetter implements adapter.CookieSetter using plain http.SetCookie,
// so session functions can be tested without the full infra.
type fakeCookieSetter struct{}

func (fakeCookieSetter) SetJWTCookie(_ http.ResponseWriter, _ string, _ jwt.Purpose, _ time.Duration, _ ...jwt.Option) (string, error) {
	return "", nil
}
func (fakeCookieSetter) ClearJWTCookie(_ http.ResponseWriter)                                   {}
func (fakeCookieSetter) EchoAuthCookie(_ http.ResponseWriter, _ *http.Request, _ ...jwt.Option) {}
func (fakeCookieSetter) SetCookie(w http.ResponseWriter, name, value, domain, path string, expiry time.Time, secure, httpOnly bool, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     path,
		Expires:  expiry,
		Secure:   secure,
		HttpOnly: httpOnly,
		SameSite: sameSite,
	})
}
func (fakeCookieSetter) Config() adapter.ConfigProvider { return nil }

var _ adapter.CookieSetter = fakeCookieSetter{}

func newTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&pluginDb.SocialProviderConfig{}))
	return db
}

func seedProvider(t *testing.T, db *gorm.DB, cfg *pluginDb.SocialProviderConfig) {
	require.NoError(t, cfg.SetScopes([]string{"email", "profile"}))
	require.NoError(t, db.Create(cfg).Error)
}

func TestProviderStore_LoadFromDB(t *testing.T) {
	db := newTestDB(t)

	seedProvider(t, db, &pluginDb.SocialProviderConfig{
		ProviderID:   "google",
		DisplayName:  "Google",
		ClientID:     "c1",
		ClientSecret: "s1",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserURL:      "https://openidconnect.googleapis.com/v1/userinfo",
		Enabled:      true,
		OrderIndex:   1,
	})
	seedProvider(t, db, &pluginDb.SocialProviderConfig{
		ProviderID:   "github",
		DisplayName:  "GitHub",
		ClientID:     "c2",
		ClientSecret: "s2",
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserURL:      "https://api.github.com/user",
		Enabled:      false,
		OrderIndex:   0,
	})

	store := NewProviderStore()
	require.NoError(t, store.LoadFromDB(db))

	// Only the enabled provider is loaded.
	assert.Equal(t, []string{"google"}, store.EnabledProviders())

	p, err := store.GetProvider("google")
	require.NoError(t, err)
	assert.Equal(t, "google", p.Name())

	_, err = store.GetProvider("github")
	assert.Error(t, err)
}

// newTestProvider builds a GenericOAuth2Provider pointing at mock endpoints.
func newTestProvider(idKey, tokenURL, userURL string) *GenericOAuth2Provider {
	return NewGenericOAuth2Provider(
		"test", "cid", "csecret", []string{"email"},
		"https://auth.example/authorize", tokenURL, userURL, "http://cb",
		"email", idKey, "name",
	)
}

func TestGenericOAuth2Provider_Exchange(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"abc123","email":"u@example.com","email_verified":true,"name":"Ada"}`))
	}))
	defer userSrv.Close()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	p := NewGenericOAuth2Provider(
		"test", "cid", "csecret", []string{"email"},
		"https://auth.example/authorize", tokenSrv.URL, userSrv.URL, "http://cb",
		"email", "sub", "name",
	)

	user, err := p.Exchange(t.Context(), "code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "abc123", user.ProviderUserID)
	assert.Equal(t, "u@example.com", user.Email)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, "Ada", user.Name)

	// AuthCodeURL carries PKCE params.
	url := p.AuthCodeURL("state", "challenge")
	assert.Contains(t, url, "code_challenge=challenge")
	assert.Contains(t, url, "code_challenge_method=S256")
}

func TestGenericOAuth2Provider_Exchange_MissingIDKey(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"email":"u@example.com"}`)) // no "sub" / id key
	}))
	defer userSrv.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	p := newTestProvider("sub", tokenSrv.URL, userSrv.URL)
	_, err := p.Exchange(t.Context(), "code", "verifier")
	assert.Error(t, err)
}

func TestGenericOAuth2Provider_Exchange_MissingEmailKey(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"abc123"}`)) // no email
	}))
	defer userSrv.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	p := newTestProvider("sub", tokenSrv.URL, userSrv.URL)
	_, err := p.Exchange(t.Context(), "code", "verifier")
	assert.Error(t, err)
}

// An aggregate (object/array) value for the id/email key must be rejected, not
// coerced via fmt.Sprintf into a garbage principal.
func TestGenericOAuth2Provider_Exchange_RejectsAggregateID(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":{"id":"nested"},"email":"u@example.com"}`))
	}))
	defer userSrv.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	p := newTestProvider("sub", tokenSrv.URL, userSrv.URL)
	_, err := p.Exchange(t.Context(), "code", "verifier")
	assert.Error(t, err)
}

// A numeric id must be preserved precisely (json.Number), not float-formatted.
func TestGenericOAuth2Provider_Exchange_NumericID(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":123456789012345678,"email":"u@example.com"}`))
	}))
	defer userSrv.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	p := newTestProvider("sub", tokenSrv.URL, userSrv.URL)
	user, err := p.Exchange(t.Context(), "code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "123456789012345678", user.ProviderUserID)
}

// Absent email_verified means unverified (koanf Bool defaults to false).
func TestGenericOAuth2Provider_Exchange_MissingEmailVerified(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"abc123","email":"u@example.com"}`))
	}))
	defer userSrv.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	p := newTestProvider("sub", tokenSrv.URL, userSrv.URL)
	user, err := p.Exchange(t.Context(), "code", "verifier")
	require.NoError(t, err)
	assert.False(t, user.EmailVerified)
}

// Nesting is resolved via dot-notation (koanf), e.g. id at "data.id".
func TestGenericOAuth2Provider_Exchange_NestedKeys(t *testing.T) {
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"nested-1","email":"n@example.com"}}`))
	}))
	defer userSrv.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	p := NewGenericOAuth2Provider(
		"test", "cid", "csecret", []string{"email"},
		"https://auth.example/authorize", tokenSrv.URL, userSrv.URL, "http://cb",
		"data.email", "data.id", "name",
	)

	user, err := p.Exchange(t.Context(), "code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "nested-1", user.ProviderUserID)
	assert.Equal(t, "n@example.com", user.Email)
}

func TestSessionRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	session := &SocialAuthSession{
		State:        "abc",
		CodeVerifier: "def",
		ReturnURL:    "/dashboard",
	}

	w := httptest.NewRecorder()
	require.NoError(t, SaveSession(w, session, key, fakeCookieSetter{}, "example.com"))

	cookie := w.Result().Cookies()
	require.Len(t, cookie, 1)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie[0])

	got, err := GetSession(req, key)
	require.NoError(t, err)
	assert.Equal(t, session, got)
}

func TestSessionTampered(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	w := httptest.NewRecorder()
	require.NoError(t, SaveSession(w, &SocialAuthSession{State: "abc", CodeVerifier: "def", ReturnURL: "/"}, key, fakeCookieSetter{}, "example.com"))

	cookie := w.Result().Cookies()[0]
	// Tamper with the value.
	cookie.Value = cookie.Value + "x"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	_, err := GetSession(req, key)
	assert.Error(t, err)
}
