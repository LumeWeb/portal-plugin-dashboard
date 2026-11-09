package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestAPIKeyExchange_RejectsForgedCredentialBeforeKeyLookup(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(tb, err)
		claims := gjwt.RegisteredClaims{Issuer: ctx.Config().Config().Core.Domain, Subject: "7", ID: uuid.NewString(), Audience: []string{"api"}, ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Hour))}
		token, err := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims).SignedString(private)
		require.NoError(tb, err)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/key", nil)
		req.Host = core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, false)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		ctx.Router().ServeHTTP(w, req)
		require.Equal(tb, http.StatusUnauthorized, w.Code)
		core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE).AssertNotCalled(tb, "ValidateAPIKey")
		core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE).AssertNotCalled(tb, "LoginID")
	})
}

func TestAPIKeyExchange_ValidCredentialStillLogsIn(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		keyID := uuid.New()
		token := CreateTestAPIKeyToken(tb, ctx, "7", keyID)
		keySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		keySvc.EXPECT().ValidateAPIKey(mock.Anything, uint(7), keyID).Return(&pluginDb.APIKey{UserID: 7}, nil).Once()
		auth := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		auth.EXPECT().LoginID(mock.Anything, uint(7), mock.Anything, false).Return(CreateTestJWTToken(tb, ctx, "7", jwt.PurposeLogin), nil).Once()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/key", nil)
		req.Host = core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, false)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		ctx.Router().ServeHTTP(w, req)
		require.Equal(tb, http.StatusOK, w.Code)
		require.Contains(tb, w.Body.String(), `"token":`)
	})
}
