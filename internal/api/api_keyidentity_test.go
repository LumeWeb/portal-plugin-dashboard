package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"go.lumeweb.com/portal-plugin-dashboard/internal/keyidentity"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

// ensureEthereumHandlerRegistered registers the Ethereum key identity handler
// in the core registry for tests. Must be called inside RunTestCase because
// ResetState() clears the registry between tests. Uses the production
// registration function so the dashboardDomainResolver is exercised.
func ensureEthereumHandlerRegistered() {
	reg := keyidentity.EthereumHandlerRegistration()
	core.RegisterKeyIdentity(reg.Type, reg.Handler)
}

func TestKeyIdentityChallenge_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType: "ethereum",
			Key:     "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())

		var resp dto.KeyIdentityChallengeResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Nil(tb, err)
		assert.NotEmpty(tb, resp.Message)
		assert.NotEmpty(tb, resp.Nonce)
		assert.Contains(tb, resp.Message, "account.example.com")
		// Verify the dashboard domain (subdomain + core) is used, not the
		// bare core domain. Every occurrence of "example.com" must be part
		// of "account.example.com" — the bare core domain must not appear.
		bareDomain := "example.com"
		dashDomain := "account.example.com"
		prefixLen := len(dashDomain) - len(bareDomain) // len("account.")
		for _, i := range allIndices(resp.Message, bareDomain) {
			if i < prefixLen || resp.Message[i-prefixLen:i+len(bareDomain)] != dashDomain {
				tb.Fatalf("bare core domain %q found at offset %d, not part of %q\nmessage: %q", bareDomain, i, dashDomain, resp.Message)
			}
		}
	})
}

// allIndices returns all start offsets of substr in s.
func allIndices(s, substr string) []int {
	var indices []int
	for i := 0; ; i++ {
		j := strings.Index(s[i:], substr)
		if j < 0 {
			break
		}
		indices = append(indices, i+j)
		i += j + len(substr) - 1
	}
	return indices
}

func TestKeyIdentityChallenge_UnsupportedKeyType(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType: "nonexistent",
			Key:     "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusBadRequest, w.Code)
	})
}

func TestKeyIdentityChallenge_InvalidKey(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType: "ethereum",
			Key:     "not-an-address",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusBadRequest, w.Code)
	})
}

func TestKeyIdentityChallenge_InvalidMetadata(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType:  "ethereum",
			Key:      "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
			Metadata: dto.NewJSONRawMessageSchema([]byte(`{"chain_id":"invalid"}`)),
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/challenge", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusBadRequest, w.Code)
	})
}

func TestKeyIdentityChallenge_FullFlow(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key := "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

		reqBody := dto.KeyIdentityChallengeRequest{
			KeyType: "ethereum",
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
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.Nil(tb, err)
		require.NotEmpty(tb, resp.Message)
		require.NotEmpty(tb, resp.Nonce)

		assert.Contains(tb, resp.Message, key)
		assert.Contains(tb, resp.Message, "example.com")
		assert.Contains(tb, resp.Message, resp.Nonce)
	})
}

func TestKeyIdentityVerify_InvalidLogin(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key := "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		authSvc.MockAuthService.EXPECT().LoginKeyIdentityWithContext(
			mock.Anything, "ethereum", key, mock.Anything, mock.Anything, false,
		).Return("", nil, acctErr).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "ethereum",
			Key:       key,
			Message:   "test message",
			Signature: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b",
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

func TestKeyIdentityVerify_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key := "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
		testToken := CreateTestLoginToken(tb, ctx, "1")

		authSvc.MockAuthService.EXPECT().LoginKeyIdentityWithContext(
			mock.Anything, "ethereum", key, mock.Anything, mock.Anything, false,
		).Return(testToken, nil, nil).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "ethereum",
			Key:       key,
			Message:   "test message",
			Signature: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b",
			Remember:  false,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusFound, w.Code)
		assert.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")
		authSvc.AssertExpectations(tb)
	})
}

func TestKeyIdentityVerify_OTPEnabled(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		ensureEthereumHandlerRegistered()
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		key := "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
		testToken := CreateTestLoginToken(tb, ctx, "1")
		otpUser := &models.User{
			Model:      gorm.Model{ID: 1},
			Email:      "otp@example.com",
			OTPEnabled: true,
		}

		authSvc.MockAuthService.EXPECT().LoginKeyIdentityWithContext(
			mock.Anything, "ethereum", key, mock.Anything, mock.Anything, false,
		).Return(testToken, otpUser, nil).Once()

		reqBody := dto.KeyIdentityVerifyRequest{
			KeyType:   "ethereum",
			Key:       key,
			Message:   "test message",
			Signature: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b",
			Remember:  false,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/auth/key/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(tb, http.StatusOK, w.Code, "body: %s", w.Body.String())

		var resp dto.KeyIdentityVerifyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Nil(tb, err)
		assert.True(tb, resp.Otp)
		assert.Equal(tb, testToken, resp.Token)
		authSvc.AssertExpectations(tb)
	})
}
