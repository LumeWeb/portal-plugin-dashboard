package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"go.lumeweb.com/portal-plugin-dashboard/internal/keyidentity"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
)

// ensureSolanaHandlerRegistered registers the Solana (SIWS) key identity
// handler in the core registry for tests. Must be called inside RunTestCase
// because ResetState() clears the registry between tests.
func ensureSolanaHandlerRegistered() {
	reg := keyidentity.SolanaHandlerRegistration()
	core.RegisterKeyIdentity(reg.Type, reg.Handler)
}

// solanaTestKey generates a fresh Solana address + Ed25519 private key.
func solanaTestKey(tb coreTesting.TB) (string, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(tb, err)
	return base58.Encode(pub), priv
}

func TestSolanaKeyIdentityChallenge_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key, _ := solanaTestKey(tb)

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType: "solana",
			Key:     key,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())

		var resp dto.KeyIdentityChallengeResponse
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NotEmpty(tb, resp.Message)
		require.NotEmpty(tb, resp.Nonce)

		// SIWS message must reference the Solana account, use the dashboard
		// domain (subdomain + core), and embed the nonce.
		assert.Contains(tb, resp.Message, "wants you to sign in with your Solana account")
		assert.Contains(tb, resp.Message, key)
		assert.Contains(tb, resp.Message, "account.example.com")
		assert.Contains(tb, resp.Message, resp.Nonce)
	})
}

func TestSolanaKeyIdentityChallenge_InvalidAddress(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType: "solana",
			Key:     "!!!not-base58!!!",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	})
}

func TestSolanaKeyIdentityVerify_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key, _ := solanaTestKey(tb)
		testToken := CreateTestLoginToken(tb, ctx, "1")

		userSvc.EXPECT().KeyIdentityExists(
			mock.Anything, "solana", key,
		).Return(true, &models.KeyIdentity{}, nil).Once()

		authSvc.MockAuthService.EXPECT().LoginKeyIdentityWithContext(
			mock.Anything, "solana", key, mock.Anything, mock.Anything, false,
		).Return(testToken, nil, nil).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   "test message",
			Signature: base58.Encode(make([]byte, 64)),
			Remember:  false,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		require.Equal(tb, http.StatusFound, w.Code, "body: %s", w.Body.String())
		assert.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")
		authSvc.AssertExpectations(tb)
	})
}

func TestSolanaKeyIdentityVerify_InvalidLogin(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key, _ := solanaTestKey(tb)

		userSvc.EXPECT().KeyIdentityExists(
			mock.Anything, "solana", key,
		).Return(true, &models.KeyIdentity{}, nil).Once()

		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		authSvc.MockAuthService.EXPECT().LoginKeyIdentityWithContext(
			mock.Anything, "solana", key, mock.Anything, mock.Anything, false,
		).Return("", nil, acctErr).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   "test message",
			Signature: base58.Encode(make([]byte, 64)),
			Remember:  false,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, acctErr.HttpStatus(), w.Code)
		authSvc.AssertExpectations(tb)
	})
}
