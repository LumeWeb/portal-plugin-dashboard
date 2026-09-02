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
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

// keyIdentityTestUser is the user backing the auth token in manage tests.
func keyIdentityTestUser() *models.User {
	return &models.User{Model: gorm.Model{ID: 1}, Email: "user@example.com"}
}

// keyIdentityAuthedRequest performs an authenticated request against the
// dashboard router using a Bearer login token.
func keyIdentityAuthedRequest(tb coreTesting.TB, ctx coreTesting.TestContext, method, path string, token string, body []byte) *httptest.ResponseRecorder {
	httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
	router := ctx.Router()
	domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = domain
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	return w
}

func TestKeyIdentityConnectChallenge_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		key := "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

		// AccessMiddleware resolves the user; handler normalizes the key (to
		// lowercase) before checking it is free.
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "ethereum", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").Return(false, nil, nil).Once()

		reqBody := dto.KeyIdentityChallengeRequest{KeyType: "ethereum", Key: key}
		body, _ := json.Marshal(reqBody)

		w := keyIdentityAuthedRequest(tb, ctx, "POST", "/api/auth/key/connect/challenge", token, body)

		require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())
		var resp dto.KeyIdentityChallengeResponse
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(tb, resp.Message)
		assert.Contains(tb, resp.Message, "account.example.com")
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityConnectChallenge_KeyAlreadyLinked(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		key := "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "ethereum", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").Return(true, &models.KeyIdentity{Type: "ethereum", Key: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"}, nil).Once()

		reqBody := dto.KeyIdentityChallengeRequest{KeyType: "ethereum", Key: key}
		body, _ := json.Marshal(reqBody)

		w := keyIdentityAuthedRequest(tb, ctx, "POST", "/api/auth/key/connect/challenge", token, body)

		assert.Equal(tb, http.StatusConflict, w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityConnectChallenge_UnsupportedKeyType(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()

		reqBody := dto.KeyIdentityChallengeRequest{KeyType: "bitcoin", Key: "x"}
		body, _ := json.Marshal(reqBody)

		w := keyIdentityAuthedRequest(tb, ctx, "POST", "/api/auth/key/connect/challenge", token, body)

		assert.Equal(tb, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityConnectChallenge_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		reqBody := dto.KeyIdentityChallengeRequest{KeyType: "ethereum", Key: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/connect/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
	})
}

// TestKeyIdentityConnectVerify_Success runs the real Solana SIWS crypto path
// through the dashboard: issue a challenge, sign it with Ed25519, verify, and
// bind the key to the authenticated user.
func TestKeyIdentityConnectVerify_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		key, priv := solanaTestKey(tb)

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		// Challenge phase: key must be free.
		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()

		reqBody := dto.KeyIdentityChallengeRequest{KeyType: "solana", Key: key}
		body, _ := json.Marshal(reqBody)
		w := keyIdentityAuthedRequest(tb, ctx, "POST", "/api/auth/key/connect/challenge", token, body)
		require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())

		var challenge dto.KeyIdentityChallengeResponse
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &challenge))

		// Sign the SIWS plaintext with the wallet's private key.
		sig := base58.Encode(ed25519.Sign(priv, []byte(challenge.Message)))

		// Verify phase: pre-check + bind.
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().AddKeyIdentity(mock.Anything, uint(1), "solana", key, mock.Anything).Return(nil).Once()

		verifyBody := dto.KeyIdentityConnectVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   challenge.Message,
			Signature: sig,
		}
		vb, _ := json.Marshal(verifyBody)
		w = keyIdentityAuthedRequest(tb, ctx, "POST", "/api/auth/key/connect/verify", token, vb)

		require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())
		var resp dto.KeyIdentityConnectVerifyResponse
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(tb, "solana", resp.KeyType)
		assert.Equal(tb, key, resp.Key)
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityConnectVerify_InvalidProof(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		key, _ := solanaTestKey(tb)

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()

		verifyBody := dto.KeyIdentityConnectVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   "not a real challenge message",
			Signature: base58.Encode(make([]byte, 64)),
		}
		vb, _ := json.Marshal(verifyBody)
		w := keyIdentityAuthedRequest(tb, ctx, "POST", "/api/auth/key/connect/verify", token, vb)

		assert.Equal(tb, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityDisconnect_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		key := "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().RemoveKeyIdentity(mock.Anything, uint(1), "ethereum", key).Return(nil).Once()

		w := keyIdentityAuthedRequest(tb, ctx, "DELETE", "/api/auth/key/ethereum/"+key, token, nil)

		assert.Equal(tb, http.StatusNoContent, w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityDisconnect_NotFound(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		key := "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().RemoveKeyIdentity(mock.Anything, uint(1), "ethereum", key).
			Return(core.NewAccountError(core.ErrKeyKeyIdentityNotFound, nil)).Once()

		w := keyIdentityAuthedRequest(tb, ctx, "DELETE", "/api/auth/key/ethereum/"+key, token, nil)

		assert.Equal(tb, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityList_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		token := CreateTestLoginToken(tb, ctx, "1")

		linked := &models.KeyIdentity{
			Type:     "solana",
			Key:      "linked-solana-key",
			Metadata: json.RawMessage(`{}`),
			UserID:   1,
		}

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, keyIdentityTestUser(), nil).Once()
		userSvc.EXPECT().ListKeyIdentities(mock.Anything, uint(1), mock.Anything, mock.Anything, mock.Anything).
			Return([]*models.KeyIdentity{linked}, int64(1), nil).Once()

		w := keyIdentityAuthedRequest(tb, ctx, "GET", "/api/auth/key/identities", token, nil)

		require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.Contains(tb, w.Body.String(), `"solana"`)
		assert.Contains(tb, w.Body.String(), `"linked-solana-key"`)
		userSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityManage_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		cases := []struct {
			method, path string
		}{
			{http.MethodPost, "/api/auth/key/connect/challenge"},
			{http.MethodPost, "/api/auth/key/connect/verify"},
			{http.MethodDelete, "/api/auth/key/ethereum/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"},
			{http.MethodGet, "/api/auth/key/identities"},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = domain
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(tb, http.StatusUnauthorized, w.Code, "expected 401 for %s %s, body: %s", tc.method, tc.path, w.Body.String())
		}
	})
}
