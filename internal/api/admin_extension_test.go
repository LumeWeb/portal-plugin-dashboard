package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

// adminTestOptions enables a real SQLite database and registers the social
// admin extension against a mock "admin" API on the test router.
var adminTestOptions = coreTesting.CombineOptions(
	coreTesting.WithSQLite(),
	coreTesting.WithAPIExtension(NewAdminExtension()),
)

func TestSocialAdminExtension_Identity(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		extFactory := NewAdminExtension()
		ext, _, err := extFactory()
		require.NoError(tb, err)

		adminExt := ext.(*SocialAdminExtension)
		assert.Equal(tb, "admin", adminExt.TargetAPI())
		assert.NotEmpty(tb, adminExt.ID())
		assert.NotEmpty(tb, adminExt.Name())

		var _ core.APIExtension = adminExt
	})
}

// setupAdminDB migrates the plugin table into the test's real SQLite database.
func setupAdminDB(tb testing.TB, ctx coreTesting.TestContext) {
	tb.Helper()
	require.NoError(tb, ctx.DB().AutoMigrate(&pluginDb.SocialProviderConfig{}))
}

// setupAdminAuth establishes an authenticated (login-purpose) request identity
// for the given user id, which the access mock treats as having admin access.
func setupAdminAuth(tb testing.TB, ctx coreTesting.TestContext, userID uint) string {
	tb.Helper()
	userSvc := coreTesting.GetMockUserService(ctx)
	mockUser := &models.User{Model: gorm.Model{ID: userID}, Email: "admin@example.com"}
	userSvc.EXPECT().AccountExists(mock.Anything, userID).Return(true, mockUser, nil).Maybe()
	return CreateTestLoginToken(tb, ctx, strconv.FormatUint(uint64(userID), 10))
}

func adminRequest(tb testing.TB, ctx coreTesting.TestContext, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	tb.Helper()
	req := ctx.NewAPIRequest(method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	ctx.Router().ServeHTTP(rec, req)
	return rec
}

func itoa(u uint) string {
	return strconv.FormatUint(uint64(u), 10)
}

func TestSocialAdminExtension_FullCRUD(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		setupAdminDB(tb, ctx)
		token := setupAdminAuth(tb, ctx, 1)

		createBody := []byte(`{
			"provider_id":"google",
			"display_name":"Google",
			"client_id":"cli-1",
			"client_secret":"sec-1",
			"scopes":["email","profile"],
			"auth_url":"https://accounts.google.com/o/oauth2/v2/auth",
			"token_url":"https://oauth2.googleapis.com/token",
			"user_url":"https://openidconnect.googleapis.com/v1/userinfo",
			"enabled":true,
			"order_index":1
		}`)

		// Create
		rec := adminRequest(tb, ctx, http.MethodPost, "/api/social/providers", createBody, token)
		require.Equal(tb, http.StatusCreated, rec.Code, rec.Body.String())
		var created dto.SocialProviderResponse
		require.NoError(tb, json.Unmarshal(rec.Body.Bytes(), &created))
		assert.Equal(tb, "google", created.ProviderID)
		assert.True(tb, created.Enabled)
		assert.NotZero(tb, created.ID)
		assert.NotContains(tb, rec.Body.String(), "sec-1") // secret never serialized

		// Provider cache refreshed immediately.
		assert.Contains(tb, provider.Provider().EnabledProviders(), "google")

		// Get by id
		rec = adminRequest(tb, ctx, http.MethodGet, "/api/social/providers/"+itoa(created.ID), nil, token)
		require.Equal(tb, http.StatusOK, rec.Code, rec.Body.String())

		// List
		rec = adminRequest(tb, ctx, http.MethodGet, "/api/social/providers", nil, token)
		require.Equal(tb, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(tb, rec.Body.String(), "google")
		assert.NotContains(tb, rec.Body.String(), "sec-1") // secrets never returned

		// Update
		updateBody := []byte(`{"display_name":"Google LLC","client_id":"cli-1","enabled":false}`)
		rec = adminRequest(tb, ctx, http.MethodPut, "/api/social/providers/"+itoa(created.ID), updateBody, token)
		require.Equal(tb, http.StatusOK, rec.Code, rec.Body.String())
		var updated dto.SocialProviderResponse
		require.NoError(tb, json.Unmarshal(rec.Body.Bytes(), &updated))
		assert.Equal(tb, "Google LLC", updated.DisplayName)
		assert.False(tb, updated.Enabled)
		assert.NotContains(tb, provider.Provider().EnabledProviders(), "google")

		// Disable / enable lifecycle
		rec = adminRequest(tb, ctx, http.MethodPost, "/api/social/providers/"+itoa(created.ID)+"/disable", nil, token)
		require.Equal(tb, http.StatusOK, rec.Code, rec.Body.String())
		rec = adminRequest(tb, ctx, http.MethodPost, "/api/social/providers/"+itoa(created.ID)+"/enable", nil, token)
		require.Equal(tb, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(tb, provider.Provider().EnabledProviders(), "google")

		// Delete
		rec = adminRequest(tb, ctx, http.MethodDelete, "/api/social/providers/"+itoa(created.ID), nil, token)
		require.Equal(tb, http.StatusNoContent, rec.Code, rec.Body.String())

		// Gone after delete
		rec = adminRequest(tb, ctx, http.MethodGet, "/api/social/providers/"+itoa(created.ID), nil, token)
		require.Equal(tb, http.StatusNotFound, rec.Code, rec.Body.String())
	}, adminTestOptions)
}

func TestSocialAdminExtension_ListNeverReturnsSecret(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		setupAdminDB(tb, ctx)
		token := setupAdminAuth(tb, ctx, 1)

		const secret = "super-secret-value-42"
		createBody := []byte(`{
			"provider_id":"github",
			"display_name":"GitHub",
			"client_id":"cli-2",
			"client_secret":"` + secret + `",
			"auth_url":"https://github.com/login/oauth/authorize",
			"token_url":"https://github.com/login/oauth/access_token",
			"user_url":"https://api.github.com/user",
			"enabled":false
		}`)
		require.Equal(tb, http.StatusCreated,
			adminRequest(tb, ctx, http.MethodPost, "/api/social/providers", createBody, token).Code)

		rec := adminRequest(tb, ctx, http.MethodGet, "/api/social/providers", nil, token)
		require.Equal(tb, http.StatusOK, rec.Code, rec.Body.String())
		body := rec.Body.String()

		assert.False(tb, strings.Contains(body, secret), "list response leaked client secret")
		assert.False(tb, strings.Contains(strings.ToLower(body), "client_secret"), "list response exposes secret field name")
	}, adminTestOptions)
}

func TestSocialAdminExtension_RequiresAuth(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		setupAdminDB(tb, ctx)

		// No bearer token => auth middleware rejects.
		rec := adminRequest(tb, ctx, http.MethodGet, "/api/social/providers", nil, "")
		require.Equal(tb, http.StatusUnauthorized, rec.Code, rec.Body.String())
	}, adminTestOptions)
}

func TestSocialAdminExtension_CreateValidation(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		setupAdminDB(tb, ctx)
		token := setupAdminAuth(tb, ctx, 1)

		// provider_id/client_id/client_secret are required.
		rec := adminRequest(tb, ctx, http.MethodPost, "/api/social/providers", []byte(`{"display_name":"X"}`), token)
		require.Equal(tb, http.StatusBadRequest, rec.Code, rec.Body.String())
	}, adminTestOptions)
}
