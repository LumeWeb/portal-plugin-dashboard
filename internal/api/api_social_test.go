package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/httputil"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// socialTestOptions registers the mock social auth service so the API wires it
// into the socialAuth field during startup.
var socialTestOptions = coreTesting.CombineOptions(
	coreTesting.WithMockServiceFactory(core.SOCIAL_AUTH_SERVICE, func(tb interface {
		mock.TestingT
		Cleanup(func())
	}) *coreTesting.MockSocialAuthService {
		return &coreTesting.MockSocialAuthService{
			MockSocialAuthService: mocks.NewMockSocialAuthService(tb),
		}
	}),
)

// newSocialTestContext builds an httputil.RequestContext and recorder useful for
// calling handlers directly.
func newSocialTestContext(t testing.TB) (httputil.RequestContext, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	echoCtx := e.NewContext(req, w)
	return httputil.Context(echoCtx), w
}

// socialTestAPI returns the plugin API with the mock social auth service wired in.
func socialTestAPI(ctx coreTesting.TestContext) (*API, *coreTesting.MockSocialAuthService) {
	api := core.GetAPI(internal.PLUGIN_NAME).(*API)
	socialSvc := core.GetService[*coreTesting.MockSocialAuthService](ctx, core.SOCIAL_AUTH_SERVICE)
	api.socialAuth = socialSvc
	return api, socialSvc
}

// seedProviderDB creates an in-memory DB with a single enabled "google"
// provider pointing at the given token and userinfo server URLs.
func seedProviderDB(tb testing.TB, tokenURL, userURL string) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(tb, err)
	require.NoError(tb, db.AutoMigrate(&pluginDb.SocialProviderConfig{}))

	cfg := &pluginDb.SocialProviderConfig{
		ProviderID:   "google",
		DisplayName:  "Google",
		ClientID:     "cid",
		ClientSecret: "sec",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     tokenURL,
		UserURL:      userURL,
		UserEmailKey: "email",
		UserIDKey:    "sub",
		Enabled:      true,
	}
	require.NoError(tb, cfg.SetScopes([]string{"email"}))
	require.NoError(tb, db.Create(cfg).Error)

	return db
}

func TestFinishSocialLogin_ExistingLinkLogsIn(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)

		mockUser := &models.User{Model: gorm.Model{ID: 7}, Email: "linked@example.com"}
		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-1", "linked@example.com", true).
			Return(&core.SocialAuthResult{User: mockUser}, nil)
		loginToken := CreateTestLoginToken(tb, ctx, "7")
		authSvc.EXPECT().LoginID(mock.Anything, uint(7), mock.Anything, false).Return(loginToken, nil)

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-1", Email: "linked@example.com"}, "/dashboard")
		require.NoError(tb, err)
		require.Equal(tb, http.StatusFound, w.Code)
		require.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")
	}, socialTestOptions)
}

// SSO auto-verifies email: even when the provider does NOT confirm the email,
// LoginOrLink is called with emailVerified=true and a session is established.
func TestFinishSocialLogin_SSOAutoVerifiesEmail(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)

		// Provider explicitly reports email NOT verified.
		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-2", "unverified@example.com", true).
			Return(&core.SocialAuthResult{
				User:          &models.User{Model: gorm.Model{ID: 8}, Email: "unverified@example.com"},
				EmailVerified: false,
			}, nil)
		loginToken := CreateTestLoginToken(tb, ctx, "8")
		authSvc.EXPECT().LoginID(mock.Anything, uint(8), mock.Anything, false).Return(loginToken, nil)

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-2", Email: "unverified@example.com", EmailVerified: false}, "/")
		require.NoError(tb, err)
		// Session is established despite unverified email.
		require.Equal(tb, http.StatusFound, w.Code)
		require.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")
	}, socialTestOptions)
}

func TestFinishSocialLogin_EmailConflict(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)

		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-3", "taken@example.com", true).
			Return(nil, core.NewAccountError(core.ErrKeySocialEmailConflict, nil))

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-3", Email: "taken@example.com"}, "/")
		require.Error(tb, err)
		require.Equal(tb, http.StatusConflict, w.Code)
	}, socialTestOptions)
}

func TestCompleteSocialLink_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)

		socialSvc.EXPECT().LinkAccount(mock.Anything, uint(9), "google", "uid-9", "x@example.com").
			Return(nil)

		reqCtx, w := newSocialTestContext(t)
		session := &provider.SocialAuthSession{Mode: provider.SessionModeLink, UserID: 9, ReturnURL: "/settings"}
		err := api.completeSocialLink(reqCtx, "google", session,
			&provider.OAuth2User{ProviderUserID: "uid-9", Email: "x@example.com"})
		require.NoError(tb, err)
		require.Equal(tb, http.StatusFound, w.Code)
		require.Equal(tb, "/settings", w.Header().Get("Location"))
	}, socialTestOptions)
}

func TestCompleteSocialLink_AlreadyLinked(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)

		socialSvc.EXPECT().LinkAccount(mock.Anything, uint(9), "google", "uid-9", "x@example.com").
			Return(core.NewAccountError(core.ErrKeySocialAlreadyLinked, nil))

		reqCtx, w := newSocialTestContext(t)
		session := &provider.SocialAuthSession{Mode: provider.SessionModeLink, UserID: 9, ReturnURL: "/settings"}
		err := api.completeSocialLink(reqCtx, "google", session,
			&provider.OAuth2User{ProviderUserID: "uid-9", Email: "x@example.com"})
		require.Error(tb, err)
		require.Equal(tb, http.StatusConflict, w.Code)
	}, socialTestOptions)
}

func TestListSocialLinks(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)

		acct := &models.SocialAccount{
			Model:          gorm.Model{ID: 1},
			Provider:       "google",
			ProviderUserID: "uid-1",
			Email:          "u@example.com",
		}
		socialSvc.EXPECT().ListAccounts(mock.Anything, uint(5)).Return([]*models.SocialAccount{acct}, nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/links", nil)
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)
		echoCtx.Set(string(mcontext.UserIDKey), uint(5))

		require.NoError(tb, api.listSocialLinks(echoCtx))
		require.Equal(tb, http.StatusOK, w.Code)
		var links []map[string]any
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &links))
		require.Len(tb, links, 1)
		require.Equal(tb, "google", links[0]["provider"])
	}, socialTestOptions)
}

func TestSocialAuthUnlink(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)

		socialSvc.EXPECT().UnlinkAccount(mock.Anything, uint(5), "google").Return(nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/api/account/auth/sso/google", nil)
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)
		echoCtx.Set(string(mcontext.UserIDKey), uint(5))
		echoCtx.SetParamNames("provider")
		echoCtx.SetParamValues("google")

		require.NoError(tb, api.socialAuthUnlink(echoCtx))
		require.Equal(tb, http.StatusNoContent, w.Code)
	}, socialTestOptions)
}

func TestSocialAuthCallback_LoginFlow(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)

		userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"uid-1","email":"u@example.com","email_verified":true}`))
		}))
		defer userSrv.Close()
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
		}))
		defer tokenSrv.Close()

		store := provider.Provider()
		store.SetContext(ctx)
		require.NoError(tb, store.LoadFromDB(seedProviderDB(tb, tokenSrv.URL, userSrv.URL)))
		api.providerStore = store

		// Write a login-mode session cookie.
		key, err := api.socialSessionKey()
		require.NoError(tb, err)
		session := &provider.SocialAuthSession{State: "state-abc", CodeVerifier: "verifier-xyz", ReturnURL: "/dashboard"}
		cookW := httptest.NewRecorder()
		require.NoError(tb, provider.SaveSession(cookW, session, key, api.cookieSetter(), api.Config().Config().Core.Domain))
		cookies := cookW.Result().Cookies()
		require.Len(tb, cookies, 1)

		mockUser := &models.User{Model: gorm.Model{ID: 7}, Email: "u@example.com"}
		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-1", "u@example.com", true).
			Return(&core.SocialAuthResult{User: mockUser}, nil)
		loginToken := CreateTestLoginToken(tb, ctx, "7")
		authSvc.EXPECT().LoginID(mock.Anything, uint(7), mock.Anything, false).Return(loginToken, nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/sso/google/callback?state=state-abc&code=code-1", nil)
		req.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)
		echoCtx.SetParamNames("provider")
		echoCtx.SetParamValues("google")

		require.NoError(tb, api.socialAuthCallback(echoCtx))
		require.Equal(tb, http.StatusFound, w.Code)
		require.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")
	}, socialTestOptions)
}

func TestSocialAuthCallback_LinkFlow(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)

		userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"uid-9","email":"x@example.com"}`))
		}))
		defer userSrv.Close()
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
		}))
		defer tokenSrv.Close()

		store := provider.Provider()
		store.SetContext(ctx)
		require.NoError(tb, store.LoadFromDB(seedProviderDB(tb, tokenSrv.URL, userSrv.URL)))
		api.providerStore = store

		// Write a link-mode session cookie.
		key, err := api.socialSessionKey()
		require.NoError(tb, err)
		session := &provider.SocialAuthSession{State: "state-abc", CodeVerifier: "verifier-xyz", ReturnURL: "/settings", Mode: provider.SessionModeLink, UserID: 9}
		cookW := httptest.NewRecorder()
		require.NoError(tb, provider.SaveSession(cookW, session, key, api.cookieSetter(), api.Config().Config().Core.Domain))
		cookies := cookW.Result().Cookies()
		require.Len(tb, cookies, 1)

		socialSvc.EXPECT().LinkAccount(mock.Anything, uint(9), "google", "uid-9", "x@example.com").Return(nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/sso/google/callback?state=state-abc&code=code-1", nil)
		req.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)
		echoCtx.SetParamNames("provider")
		echoCtx.SetParamValues("google")

		require.NoError(tb, api.socialAuthCallback(echoCtx))
		require.Equal(tb, http.StatusFound, w.Code)
		require.Equal(tb, "/settings", w.Header().Get("Location"))
	}, socialTestOptions)
}

// Login without a ?return query param must not 400; it defaults to "/".
func TestSocialAuthLogin_DefaultsReturnURL(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
		}))
		defer tokenSrv.Close()
		userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"uid-1","email":"u@example.com"}`))
		}))
		defer userSrv.Close()

		store := provider.Provider()
		store.SetContext(ctx)
		require.NoError(tb, store.LoadFromDB(seedProviderDB(tb, tokenSrv.URL, userSrv.URL)))
		api.providerStore = store

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/sso/google", nil)
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)
		echoCtx.SetParamNames("provider")
		echoCtx.SetParamValues("google")

		require.NoError(tb, api.socialAuthLogin(echoCtx))
		require.Equal(tb, http.StatusFound, w.Code)
		require.Contains(tb, w.Header().Get("Location"), "https://")
	}, socialTestOptions)
}
