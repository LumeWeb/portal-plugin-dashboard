package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

func TestSocialAuthCallback_RejectsConsentSession(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, social := socialTestAPI(ctx)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/token" {
				_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer"}`))
			} else {
				_, _ = w.Write([]byte(`{"sub":"uid-1","email":"u@example.com","email_verified":true}`))
			}
		}))
		defer server.Close()
		store := provider.Provider()
		store.SetContext(ctx)
		require.NoError(tb, store.LoadFromDB(seedProviderDB(tb, server.URL+"/token", server.URL+"/user")))
		api.providerStore = store
		social.EXPECT().LoginOrLink(mock.Anything, "google", "uid-1", "u@example.com", true).Return(&core.SocialAuthResult{User: &models.User{Model: gorm.Model{ID: 7}}, EmailVerified: true}, nil).Maybe()
		core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE).EXPECT().LoginID(mock.Anything, uint(7), mock.Anything, false).Return(CreateTestLoginToken(tb, ctx, "7"), nil).Maybe()
		key, err := api.socialSessionKey()
		require.NoError(tb, err)
		w := httptest.NewRecorder()
		require.NoError(tb, provider.SaveSession(w, &provider.SocialAuthSession{Mode: provider.SessionModeConsentLink, ProviderName: "google", State: "state"}, key, api.cookieSetter(), api.Config().Config().Core.Domain))
		req := httptest.NewRequest(http.MethodGet, "/api/account/auth/sso/google/callback?state=state&code=code", nil)
		req.AddCookie(w.Result().Cookies()[0])
		response := httptest.NewRecorder()
		c := echo.New().NewContext(req, response)
		c.SetParamNames("provider")
		c.SetParamValues("google")
		require.NoError(tb, api.socialAuthCallback(c))
		require.Equal(tb, http.StatusBadRequest, response.Code)
		social.AssertNotCalled(tb, "LoginOrLink")
	}, socialTestOptions)
}
