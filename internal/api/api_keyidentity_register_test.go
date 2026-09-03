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

// TestKeyIdentityRegister_OTPJSONResponse keeps new_account on the wire for
// the JSON (OTP) response path: EncodeResponse routes through FromModel,
// which must propagate the flag.
func TestKeyIdentityRegister_OTPJSONResponse(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, priv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, priv)

		anonUser := &models.User{
			Model:      gorm.Model{ID: 7},
			Email:      core.AnonEmail(key),
			OTPEnabled: true,
		}
		testToken := CreateTestLoginToken(tb, ctx, "7")

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().CreateAccount(
			mock.Anything, core.AnonEmail(key), mock.Anything, false, mock.Anything,
		).Return(anonUser, nil).Once()
		userSvc.EXPECT().UpdateAccountInfo(mock.Anything, uint(7), mock.Anything).Return(nil).Once()
		userSvc.EXPECT().AddKeyIdentity(mock.Anything, uint(7), "solana", key, mock.Anything).Return(nil).Once()
		authSvc.MockAuthService.EXPECT().LoginID(
			mock.Anything, uint(7), mock.Anything, false,
		).Return(testToken, nil).Once()

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

		require.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())
		var resp dto.KeyIdentityVerifyResponse
		require.NoError(tb, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(tb, testToken, resp.Token)
		assert.True(tb, resp.Otp)
		assert.True(tb, resp.NewAccount, "new_account must survive FromModel/EncodeResponse")
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
// (e.g. the anon email colliding with an account but the key still unlinked)
// with their status.
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
		// Collision re-check: key still unlinked → surface the error.
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

		acctErr := core.NewAccountError(core.ErrKeyEmailAlreadyExists, nil)
		assert.Equal(tb, acctErr.HttpStatus(), w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

// TestKeyIdentityRegister_RaceCollisionLogsIn covers the loser of a
// concurrent registration race: the anon email collides, but the key is
// already linked by the winner, so the request falls through to the normal
// login path instead of failing.
func TestKeyIdentityRegister_RaceCollisionLogsIn(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, priv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, priv)

		existing := &models.User{Model: gorm.Model{ID: 3}, Email: core.AnonEmail(key)}
		testToken := CreateTestLoginToken(tb, ctx, "3")

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().CreateAccount(
			mock.Anything, core.AnonEmail(key), mock.Anything, false, mock.Anything,
		).Return(existing, core.NewAccountError(core.ErrKeyEmailAlreadyExists, nil)).Once()
		// Collision re-check: the winner linked the key already.
		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(true, &models.KeyIdentity{}, nil).Once()
		authSvc.MockAuthService.EXPECT().LoginKeyIdentityWithContext(
			mock.Anything, "solana", key, mock.Anything, mock.Anything, false,
		).Return(testToken, existing, nil).Once()

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
		// The account was provisioned by the concurrent winner, not here.
		assert.NotContains(tb, w.Header().Get("Location"), "new_account=1")
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

// TestKeyIdentityRegister_KeepsLinkedAccountOnTokenFailure ensures a token
// issuance failure after the key was linked does NOT delete the account —
// the wallet itself is a working login credential at that point, so a retry
// can complete through a normal wallet login.
func TestKeyIdentityRegister_KeepsLinkedAccountOnTokenFailure(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, priv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, priv)

		anonUser := &models.User{Model: gorm.Model{ID: 9}, Email: core.AnonEmail(key)}
		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, nil)

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().CreateAccount(
			mock.Anything, core.AnonEmail(key), mock.Anything, false, mock.Anything,
		).Return(anonUser, nil).Once()
		userSvc.EXPECT().UpdateAccountInfo(mock.Anything, uint(9), mock.Anything).Return(nil).Once()
		userSvc.EXPECT().AddKeyIdentity(mock.Anything, uint(9), "solana", key, mock.Anything).Return(nil).Once()
		authSvc.MockAuthService.EXPECT().LoginID(mock.Anything, uint(9), mock.Anything, false).
			Return("", acctErr).Once()
		// Deliberately no DeleteAccount expectation: an unexpected DeleteAccount
		// call would panic and fail the test, proving the account survives.

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

		assert.Equal(tb, acctErr.HttpStatus(), w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

// TestKeyIdentityRegister_RollsBackOrphanAccount ensures a failure after
// account creation (link step) removes the otherwise inaccessible account.
func TestKeyIdentityRegister_RollsBackOrphanAccount(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureSolanaHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)

		key, priv := solanaTestKey(tb)
		message, signature := issueAndSignSolanaChallenge(tb, ctx, key, priv)

		anonUser := &models.User{Model: gorm.Model{ID: 9}, Email: core.AnonEmail(key)}

		userSvc.EXPECT().KeyIdentityExists(mock.Anything, "solana", key).Return(false, nil, nil).Once()
		userSvc.EXPECT().CreateAccount(
			mock.Anything, core.AnonEmail(key), mock.Anything, false, mock.Anything,
		).Return(anonUser, nil).Once()
		userSvc.EXPECT().UpdateAccountInfo(mock.Anything, uint(9), mock.Anything).Return(nil).Once()
		userSvc.EXPECT().AddKeyIdentity(mock.Anything, uint(9), "solana", key, mock.Anything).
			Return(core.NewAccountError(core.ErrKeyKeyIdentityExists, nil)).Once()
		// Orphan cleanup.
		userSvc.EXPECT().DeleteAccount(mock.Anything, uint(9)).Return(nil).Once()

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

		acctErr := core.NewAccountError(core.ErrKeyKeyIdentityExists, nil)
		assert.Equal(tb, acctErr.HttpStatus(), w.Code, "body: %s", w.Body.String())
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}
