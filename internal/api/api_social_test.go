package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/httputil"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/queryutil"
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
		// Existing link whose email was verified at creation; provider reports
		// verified, so emailVerified=false param is expected to not gate login.
		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-1", "linked@example.com", false).
			Return(&core.SocialAuthResult{User: mockUser, EmailVerified: true}, nil)
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

// When the provider does NOT confirm the email, the account is created
// unverified and the user must verify the address before a session is set up.
func TestFinishSocialLogin_UnverifiedEmailRequiresVerification(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)

		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-2", "unverified@example.com", false).
			Return(&core.SocialAuthResult{
				User:          &models.User{Model: gorm.Model{ID: 8}, Email: "unverified@example.com"},
				EmailVerified: false,
			}, nil)
		userSvc.EXPECT().SendEmailVerification(mock.Anything, uint(8)).Return(nil)

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-2", Email: "unverified@example.com", EmailVerified: false}, "/")
		require.NoError(tb, err)
		// No session: redirected to the verification page instead of auth-complete.
		require.Equal(tb, http.StatusFound, w.Code)
		require.Equal(tb, "/verify-email", w.Header().Get("Location"))
		authSvc.AssertNotCalled(tb, "LoginID")
	}, socialTestOptions)
}

// A failed verification-email send must surface as an error, not redirect.
func TestFinishSocialLogin_UnverifiedEmailSendFailure(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)

		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-2", "unverified@example.com", false).
			Return(&core.SocialAuthResult{
				User:          &models.User{Model: gorm.Model{ID: 8}, Email: "unverified@example.com"},
				EmailVerified: false,
			}, nil)
		userSvc.EXPECT().SendEmailVerification(mock.Anything, uint(8)).
			Return(errors.New("mailer down"))

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-2", Email: "unverified@example.com", EmailVerified: false}, "/")
		require.Error(tb, err)
		require.Equal(tb, http.StatusInternalServerError, w.Code)
	}, socialTestOptions)
}

func TestFinishSocialLogin_UnverifiedEmailConflictRejected(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)

		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-3", "taken@example.com", false).
			Return(nil, core.NewAccountError(core.ErrKeySocialEmailConflict, nil))

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-3", Email: "taken@example.com"}, "/")
		require.Error(tb, err)
		require.Equal(tb, http.StatusConflict, w.Code)
		userSvc.AssertNotCalled(tb, "EmailExists")
	}, socialTestOptions)
}

// A verified email that already belongs to a user must NOT be linked silently:
// the flow redirects to the consent page, and no LinkAccount happens yet.
func TestFinishSocialLogin_VerifiedEmailConflictRedirectsToConsent(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)

		existing := &models.User{Model: gorm.Model{ID: 12}, Email: "taken@example.com"}
		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-3", "taken@example.com", true).
			Return(nil, core.NewAccountError(core.ErrKeySocialEmailConflict, nil))
		userSvc.EXPECT().EmailExists(mock.Anything, "taken@example.com").Return(true, existing, nil)

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-3", Email: "taken@example.com", EmailVerified: true}, "/dashboard")
		require.NoError(tb, err)
		require.Equal(tb, http.StatusFound, w.Code)
		require.Equal(tb, "/api/account/auth/sso/google/consent", w.Header().Get("Location"))
		// Nothing is linked and no session is established without consent.
		socialSvc.AssertNotCalled(tb, "LinkAccount")
		authSvc.AssertNotCalled(tb, "LoginID")
	}, socialTestOptions)
}

// Prompting consent requires the email to still belong to an existing account;
// a stale conflict keeps the original rejection.
func TestFinishSocialLogin_ConsentPromptEmailGone(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)

		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-3", "taken@example.com", true).
			Return(nil, core.NewAccountError(core.ErrKeySocialEmailConflict, nil))
		userSvc.EXPECT().EmailExists(mock.Anything, "taken@example.com").Return(false, nil, nil)

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-3", Email: "taken@example.com", EmailVerified: true}, "/")
		require.Error(tb, err)
		require.Equal(tb, http.StatusConflict, w.Code)
		socialSvc.AssertNotCalled(tb, "LinkAccount")
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
		// ProcessListRequest passes parsed defaults (empty slices + default
		// pagination), so match any queryutil args.
		socialSvc.EXPECT().
			ListAccounts(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return([]*models.SocialAccount{acct}, int64(1), nil)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/links", nil)
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)
		echoCtx.Set(string(mcontext.UserIDKey), uint(5))

		require.NoError(tb, api.listSocialLinks(echoCtx))
		require.Equal(tb, http.StatusOK, w.Code)
		// ProcessListRequest returns the standard queryutil.Response envelope.
		var resp queryutil.Response[[]map[string]any]
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Len(tb, resp.Data, 1)
		require.Equal(tb, int64(1), resp.Total)
		require.Equal(tb, "google", resp.Data[0]["provider"])
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
			Return(&core.SocialAuthResult{User: mockUser, EmailVerified: true}, nil)
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

// A valid consent session renders the consent page with the provider name and
// the email the link resolves to.
func TestSocialConsentPage_Renders(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		// Serve a provider so the page can resolve its display name.
		store := provider.Provider()
		store.SetContext(ctx)
		require.NoError(tb, store.LoadFromDB(seedProviderDB(tb, "http://token.invalid", "http://user.invalid")))
		api.providerStore = store

		consentSession(tb, api, provider.SocialAuthSession{
			Mode:           provider.SessionModeConsentLink,
			ReturnURL:      "/dashboard",
			ProviderName:   "google",
			ProviderUserID: "uid-3",
			Email:          "taken@example.com",
		}, func(cookies []*http.Cookie) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/account/auth/sso/google/consent", nil)
			for _, ck := range cookies {
				req.AddCookie(ck)
			}
			w := httptest.NewRecorder()
			echoCtx := e.NewContext(req, w)
			echoCtx.SetParamNames("provider")
			echoCtx.SetParamValues("google")

			require.NoError(tb, api.socialConsentPage(echoCtx))
			require.Equal(tb, http.StatusOK, w.Code)
			body := w.Body.String()
			require.Contains(tb, body, "Link Google to your account?")
			require.Contains(tb, body, "taken@example.com")
			require.Contains(tb, body, "data-action=\"approve\"")
			// The provider user id / session state must never be rendered.
			require.NotContains(tb, body, "uid-3")
		})
	}, socialTestOptions)
}

// Without a valid consent session the consent page redirects home and renders
// nothing.
func TestSocialConsentPage_NoSessionRedirectsHome(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/sso/google/consent", nil)
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)

		require.NoError(tb, api.socialConsentPage(echoCtx))
		require.Equal(tb, http.StatusFound, w.Code)
		require.Equal(tb, "/", w.Header().Get("Location"))
		require.Empty(tb, w.Body.String())
	}, socialTestOptions)
}

// Approving the consent links the pending identity to the account that holds
// the email and returns the auth-complete redirect URI as JSON.
func TestSocialConsentSubmit_Approve(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)

		existing := &models.User{Model: gorm.Model{ID: 12}, Email: "taken@example.com"}
		userSvc.EXPECT().EmailExists(mock.Anything, "taken@example.com").Return(true, existing, nil)
		socialSvc.EXPECT().LinkAccount(mock.Anything, uint(12), "google", "uid-3", "taken@example.com").Return(nil)
		loginToken := CreateTestLoginToken(tb, ctx, "12")
		authSvc.EXPECT().LoginID(mock.Anything, uint(12), mock.Anything, false).Return(loginToken, nil)

		consentSession(tb, api, provider.SocialAuthSession{
			Mode:           provider.SessionModeConsentLink,
			ReturnURL:      "/dashboard",
			ProviderName:   "google",
			ProviderUserID: "uid-3",
			Email:          "taken@example.com",
		}, func(cookies []*http.Cookie) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent",
				strings.NewReader(`{"approve":true}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://example.com")
			for _, ck := range cookies {
				req.AddCookie(ck)
			}
			w := httptest.NewRecorder()
			echoCtx := e.NewContext(req, w)

			require.NoError(tb, api.socialConsentSubmit(echoCtx))
			require.Equal(tb, http.StatusOK, w.Code)
			var resp dto.SocialConsentResponse
			require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
			require.Contains(tb, resp.RedirectURI, "/api/auth/complete")
		})
	}, socialTestOptions)
}

// Rejecting the consent clears the pending session and sends the user home.
func TestSocialConsentSubmit_Reject(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)

		consentSession(tb, api, provider.SocialAuthSession{
			Mode:           provider.SessionModeConsentLink,
			ReturnURL:      "/dashboard",
			ProviderName:   "google",
			ProviderUserID: "uid-3",
			Email:          "taken@example.com",
		}, func(cookies []*http.Cookie) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent",
				strings.NewReader(`{"approve":false}`))
			req.Header.Set("Content-Type", "application/json")
			for _, ck := range cookies {
				req.AddCookie(ck)
			}
			w := httptest.NewRecorder()
			echoCtx := e.NewContext(req, w)

			require.NoError(tb, api.socialConsentSubmit(echoCtx))
			require.Equal(tb, http.StatusOK, w.Code)
			var resp dto.SocialConsentResponse
			require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
			require.Equal(tb, "/", resp.RedirectURI)
			// Nothing linked or logged in on reject.
			userSvc.AssertNotCalled(tb, "EmailExists")
			socialSvc.AssertNotCalled(tb, "LinkAccount")
		})
	}, socialTestOptions)
}

// A stale or forged consent session cannot link anything: the pending cookie is
// cleared and the response points home.
func TestSocialConsentSubmit_NoSession(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent",
			strings.NewReader(`{"approve":true}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		echoCtx := e.NewContext(req, w)

		require.NoError(tb, api.socialConsentSubmit(echoCtx))
		require.Equal(tb, http.StatusBadRequest, w.Code)
		// A redirect payload sends the consent page home, not an error body.
		require.Contains(tb, w.Body.String(), `"redirect_uri":"/"`)
		socialSvc.AssertNotCalled(tb, "LinkAccount")
		userSvc.AssertNotCalled(tb, "EmailExists")
	}, socialTestOptions)
}

// If the email no longer belongs to an account by the time the user approves,
// nothing is linked and the response points home.
func TestSocialConsentSubmit_EmailGone(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)

		userSvc.EXPECT().EmailExists(mock.Anything, "taken@example.com").Return(false, nil, nil)

		consentSession(tb, api, provider.SocialAuthSession{
			Mode:           provider.SessionModeConsentLink,
			ProviderName:   "google",
			ProviderUserID: "uid-3",
			Email:          "taken@example.com",
		}, func(cookies []*http.Cookie) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent",
				strings.NewReader(`{"approve":true}`))
			req.Header.Set("Content-Type", "application/json")
			for _, ck := range cookies {
				req.AddCookie(ck)
			}
			w := httptest.NewRecorder()
			echoCtx := e.NewContext(req, w)

			require.NoError(tb, api.socialConsentSubmit(echoCtx))
			require.Equal(tb, http.StatusBadRequest, w.Code)
			require.Contains(tb, w.Body.String(), `"redirect_uri":"/"`)
			socialSvc.AssertNotCalled(tb, "LinkAccount")
		})
	}, socialTestOptions)
}

// consentSession writes a consent-mode session cookie and invokes the callback
// with the resulting cookies, mirroring the redirect the browser would carry.
func consentSession(tb testing.TB, api *API, session provider.SocialAuthSession, fn func([]*http.Cookie)) {
	tb.Helper()
	key, err := api.socialSessionKey()
	require.NoError(tb, err)
	cookW := httptest.NewRecorder()
	require.NoError(tb, provider.SaveSession(cookW, &session, key, api.cookieSetter(), api.Config().Config().Core.Domain))
	cookies := cookW.Result().Cookies()
	require.Len(tb, cookies, 1)
	fn(cookies)
}

// The consent POST is served on the API subdomain; a same-origin approve from
// that host must pass the CSRF guard (not 403 against the bare core domain).
// Browsers always send Origin with a scheme, so the test uses a scheme'd URL
// even though the resolver may return a bare host.
func TestVerifySameOrigin_AllowsAPISubdomain(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		apiHost := api.http.APISubdomain(api.Name(), true)
		require.NotEmpty(tb, apiHost)
		// Sanity: the middleware target differs from the bare core domain, so
		// this test actually exercises the subdomain path.
		require.NotEqual(tb, api.Config().Config().Core.Domain, apiHost)

		origin := "https://" + strings.TrimPrefix(strings.TrimPrefix(apiHost, "https://"), "http://")

		called := false
		handler := api.verifySameOrigin()(func(c echo.Context) error {
			called = true
			return nil
		})

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent", nil)
		req.Header.Set("Origin", origin)
		echoCtx := e.NewContext(req, httptest.NewRecorder())

		require.NoError(tb, handler(echoCtx))
		require.True(tb, called)
	}, socialTestOptions)
}

func TestVerifySameOrigin_RejectsCrossOrigin(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		handler := api.verifySameOrigin()(func(c echo.Context) error { return nil })

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent", nil)
		req.Header.Set("Origin", "https://evil.example.net")
		echoCtx := e.NewContext(req, httptest.NewRecorder())

		err := handler(echoCtx)
		require.Error(tb, err)
		httpErr, ok := err.(*echo.HTTPError)
		require.True(tb, ok)
		require.Equal(tb, http.StatusForbidden, httpErr.Code)
	}, socialTestOptions)
}

// A client that strips Origin (privacy mode/webview) still sets Sec-Fetch-Site;
// a genuine same-origin fetch from the consent page must pass.
func TestVerifySameOrigin_NoOriginButSameSiteFetchMetadata(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		called := false
		handler := api.verifySameOrigin()(func(c echo.Context) error {
			called = true
			return nil
		})

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		echoCtx := e.NewContext(req, httptest.NewRecorder())

		require.NoError(tb, handler(echoCtx))
		require.True(tb, called)
	}, socialTestOptions)
}

// With no Origin and no fetch metadata, the request fails closed.
func TestVerifySameOrigin_NoOriginNoFetchMetadataRejected(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		handler := api.verifySameOrigin()(func(c echo.Context) error { return nil })

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent", nil)
		echoCtx := e.NewContext(req, httptest.NewRecorder())

		err := handler(echoCtx)
		require.Error(tb, err)
		httpErr, ok := err.(*echo.HTTPError)
		require.True(tb, ok)
		require.Equal(tb, http.StatusForbidden, httpErr.Code)
	}, socialTestOptions)
}

// An opaque Origin ("null", sandboxed iframe) must be rejected even when
// fetch metadata is absent.
func TestVerifySameOrigin_NullOriginRejected(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)

		handler := api.verifySameOrigin()(func(c echo.Context) error { return nil })

		for _, origin := range []string{"null", "http://null", ""} {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent", nil)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			echoCtx := e.NewContext(req, httptest.NewRecorder())

			err := handler(echoCtx)
			require.Error(tb, err, "origin %q should be rejected", origin)
			httpErr, ok := err.(*echo.HTTPError)
			require.True(tb, ok)
			require.Equal(tb, http.StatusForbidden, httpErr.Code)
		}
	}, socialTestOptions)
}
