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

// requestKeyIdentity performs an unauthenticated request against the
// dashboard router (key identity challenge/verify are public).
func requestKeyIdentity(tb coreTesting.TB, ctx coreTesting.TestContext, method, path string, body []byte) *httptest.ResponseRecorder {
	httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
	router := ctx.Router()
	domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = domain
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	return w
}

// issueAndSignSolanaChallenge runs a real challenge request and signs the
// returned SIWS message, mirroring what a wallet client does.
func issueAndSignSolanaChallenge(tb coreTesting.TB, ctx coreTesting.TestContext, key string, priv ed25519.PrivateKey) (message, nonce string) {
	reqBody := dto.KeyIdentityChallengeRequest{KeyType: "solana", Key: key}
	body, err := json.Marshal(reqBody)
	require.NoError(tb, err)

	w := requestKeyIdentity(tb, ctx, "POST", "/api/auth/key/challenge", body)
	require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var challenge dto.KeyIdentityChallengeResponse
	require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.NotEmpty(tb, challenge.Message)
	require.NotEmpty(tb, challenge.Nonce)

	sig := ed25519.Sign(priv, []byte(challenge.Message))
	return challenge.Message, base58.Encode(sig)
}

// TestKeyIdentityRegister_AnonAccount_Success covers the full registration
// path: an unlinked key with a valid signed challenge provisions a new
// anonymous account (generated email), links the key identity, and issues a
// login token; the redirect flags new_account.
func TestKeyIdentityRegister_AnonAccount_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, priv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, priv)

		anonUser := &models.User{
			Model: gorm.Model{ID: 7},
			Email: core.AnonEmail(key),
		}

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().CreateAccount(
			mock.Anything, core.AnonEmail(key), mock.Anything, false, mock.Anything,
		).Return(anonUser, nil).Once()
		userSvc.EXPECT().UpdateAccountInfo(mock.Anything, uint(7), mock.Anything).Return(nil).Once()
		userSvc.EXPECT().AddKeyIdentity(mock.Anything, uint(7), "solana", key, mock.Anything).Return(nil).Once()
		authSvc.MockAuthService.EXPECT().LoginID(
			mock.Anything, uint(7), mock.Anything, false,
		).Return("test-token", nil).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   message,
			Signature: signature,
			Remember:  false,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(tb, err)

		w := requestKeyIdentity(tb, ctx, "POST", "/api/auth/key/verify", body)

		require.Equal(tb, http.StatusFound, w.Code, "body: %s", w.Body.String())
		location := w.Header().Get("Location")
		assert.Contains(tb, location, "/api/auth/complete")
		assert.Contains(tb, location, "new_account=1")
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

// TestKeyIdentityRegister_InvalidProof ensures a valid signature from the
// wrong key fails proof verification instead of creating an account.
func TestKeyIdentityRegister_InvalidProof(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, _ := solanaTestKey(tb)
		_, otherPriv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, otherPriv)

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   message,
			Signature: signature,
			Remember:  false,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(tb, err)

		w := requestKeyIdentity(tb, ctx, "POST", "/api/auth/key/verify", body)

		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		assert.Equal(tb, acctErr.HttpStatus(), w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
	})
}

// TestKeyIdentityRegister_CreateAccountFailure surfaces typed account errors
// (e.g. the anon email colliding with an existing account) with their status.
func TestKeyIdentityRegister_CreateAccountFailure(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, priv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, priv)

		existing := &models.User{Model: gorm.Model{ID: 3}, Email: core.AnonEmail(key)}

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().CreateAccount(
			mock.Anything, core.AnonEmail(key), mock.Anything, false, mock.Anything,
		).Return(existing, core.NewAccountError(core.ErrKeyEmailAlreadyExists, nil)).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "solana",
			Key:       key,
			Message:   message,
			Signature: signature,
			Remember:  false,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(tb, err)

		w := requestKeyIdentity(tb, ctx, "POST", "/api/auth/key/verify", body)

		acctErr := core.NewAccountError(core.ErrKeyEmailAlreadyExists, nil)
		assert.Equal(tb, acctErr.HttpStatus(), w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}
