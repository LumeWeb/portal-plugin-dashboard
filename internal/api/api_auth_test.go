package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/portal/db/types"
	"gorm.io/gorm"
)

func TestLogin_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model:       gorm.Model{ID: 1},
			Email:       "user@example.com",
			OTPEnabled:  false,
			OTPVerified: false,
		}

		userSvc.MockUserService.EXPECT().EmailExists(mock.Anything, "user@example.com").Return(true, mockUser, nil).Once()

		// Create a valid JWT token and register it for lazy return
		testToken := CreateTestLoginToken(tb, ctx, "1")
		authSvc.RegisterLoginTokenWithUser("user@example.com", testToken, mockUser)

		// Create valid request
		reqBody := dto.LoginRequest{
			Email:    "user@example.com",
			Password: "password",
			Remember: false,
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusFound, w.Code)
		assert.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

func TestLogin_OTPRequired(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model:       gorm.Model{ID: 1},
			Email:       "user@example.com",
			OTPEnabled:  true,
			OTPVerified: true,
		}

		userSvc.MockUserService.EXPECT().EmailExists(mock.Anything, "user@example.com").Return(true, mockUser, nil).Once()

		// Create a valid JWT token for the mock to return
		testToken := CreateTestLoginToken(tb, ctx, "1")
		authSvc.MockAuthService.EXPECT().LoginPassword(mock.Anything, "user@example.com", "password", mock.Anything, false).
			Return(testToken, mockUser, nil).Once()

		// Create valid request
		reqBody := dto.LoginRequest{
			Email:    "user@example.com",
			Password: "password",
			Remember: false,
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)
		assert.NotEmpty(tb, response.Token)
		assert.True(tb, response.Otp)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

func TestLogin_InvalidCredentials(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		userSvc.MockUserService.EXPECT().EmailExists(mock.Anything, "user@example.com").Return(false, nil, nil).Once()

		// Create request with invalid credentials
		reqBody := dto.LoginRequest{
			Email:    "user@example.com",
			Password: "wrongpassword",
			Remember: false,
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
	})
}

func TestRegister_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)
		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "newuser@example.com",
		}

		userSvc.MockUserService.EXPECT().CreateAccount(mock.Anything, "newuser@example.com", "password", true).
			Return(mockUser, nil).Once()
		userSvc.MockUserService.EXPECT().UpdateAccountName(mock.Anything, uint(1), "John", "Doe").
			Return(nil).Once()

		// Create valid request
		reqBody := dto.RegisterRequest{
			Email:     "newuser@example.com",
			Password:  "password",
			FirstName: "John",
			LastName:  "Doe",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
	})
}

// TestAuthWithAPIKey_Success tests successful authentication with a valid API key
func TestAuthWithAPIKey_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock API key record
		keyUUID := types.NewBinUUID()
		mockAPIKey := &pluginDb.APIKey{
			UUID:   keyUUID,
			Name:   "test-api-key",
			UserID: 1,
		}

		// Mock expectations
		apiKeySvc.On("ValidateAPIKey", mock.Anything, uint(1), keyUUID.ToUUID()).
			Return(mockAPIKey, nil).Once()

		// Mock auth service to return a login JWT
		loginJWT := CreateTestLoginToken(tb, ctx, "1")
		authSvc.MockAuthService.EXPECT().LoginID(mock.Anything, uint(1), mock.Anything, false).
			Return(loginJWT, nil).Once()

		// Create API key JWT token
		apiKeyToken := CreateTestAPIKeyToken(tb, ctx, "1", keyUUID.ToUUID())

		// Create request
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", apiKeyToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		tb.Logf("Response status: %d", w.Code)
		tb.Logf("Response body: %s", w.Body.String())

		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)
		assert.NotEmpty(tb, response.Token)
		assert.False(tb, response.Otp)

		// Verify mock expectations
		apiKeySvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

// TestAuthWithAPIKey_InvalidToken tests authentication with an invalid API key token
func TestAuthWithAPIKey_InvalidToken(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create request with invalid token
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", "invalid.jwt.token")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify - should get 401
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

// TestAuthWithAPIKey_NoAuthorization tests authentication without authorization header
func TestAuthWithAPIKey_NoAuthorization(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create request without Authorization header
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify - should get 401
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

// TestAuthWithAPIKey_NonExistentKey tests authentication with a non-existent API key
func TestAuthWithAPIKey_NonExistentKey(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations - return error indicating invalid key
		keyUUID := uuid.New()
		apiKeySvc.On("ValidateAPIKey", mock.Anything, uint(1), keyUUID).
			Return(nil, fmt.Errorf("invalid api key")).Once()

		// Create API key JWT token
		apiKeyToken := CreateTestAPIKeyToken(tb, ctx, "1", keyUUID)

		// Create request
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", apiKeyToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify - should get 401
		assert.Equal(tb, http.StatusUnauthorized, w.Code)

		// Verify mock expectations
		apiKeySvc.AssertExpectations(tb)
	})
}

// TestAuthWithAPIKey_ExpiredToken tests authentication with an expired API key token
func TestAuthWithAPIKey_ExpiredToken(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock API key with expiration in the past
		keyUUID := types.NewBinUUID()
		_ = time.Now().Add(-1 * time.Hour) // Used only for context

		// Mock expectations - ValidateAPIKey will check expiration internally and return error
		apiKeySvc.On("ValidateAPIKey", mock.Anything, uint(1), keyUUID.ToUUID()).
			Return(nil, fmt.Errorf("invalid api key")).Once()

		// Create API key JWT token
		apiKeyToken := CreateTestAPIKeyToken(tb, ctx, "1", keyUUID.ToUUID())

		// Create request
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", apiKeyToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify - should get 401
		assert.Equal(tb, http.StatusUnauthorized, w.Code)

		// Verify mock expectations
		apiKeySvc.AssertExpectations(tb)
	})
}

// TestAuthWithAPIKey_WrongUser tests authentication with an API key from a different user
func TestAuthWithAPIKey_WrongUser(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations - return error indicating invalid key (wrong user)
		keyUUID := types.NewBinUUID()
		apiKeySvc.On("ValidateAPIKey", mock.Anything, uint(1), keyUUID.ToUUID()).
			Return(nil, fmt.Errorf("invalid api key")).Once()

		// Create API key JWT token
		apiKeyToken := CreateTestAPIKeyToken(tb, ctx, "1", keyUUID.ToUUID())

		// Create request
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", apiKeyToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify - should get 401
		assert.Equal(tb, http.StatusUnauthorized, w.Code)

		// Verify mock expectations
		apiKeySvc.AssertExpectations(tb)
	})
}

// TestAuthWithAPIKey_MalformedJTI tests authentication with a token that has malformed JTI claim
func TestAuthWithAPIKey_MalformedJTI(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create a valid login token but it doesn't have the right purpose or JTI format
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		token, err := jwt.CreateToken(
			pk,
			ctx.Config().Config().Core.Domain,
			"1",
			jwt.PurposeLogin,
			24*time.Hour,
		)
		require.NoError(tb, err, "Failed to generate test token")

		// Create request
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", token)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// This test checks behavior when token doesn't have the expected JTI format
		// The endpoint might fail during uuid.Parse(claims.ID)
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

// TestAuthWithAPIKey_MalformedSubject tests authentication with a token that has malformed subject
func TestAuthWithAPIKey_MalformedSubject(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create a token with invalid subject (not a number)
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		token, err := jwt.CreateToken(
			pk,
			ctx.Config().Config().Core.Domain,
			"not-a-number",
			jwt.PurposeAPI,
			24*time.Hour,
			jwt.WithClaims(&jwt.RegisteredClaims{
				ID: uuid.New().String(),
			}),
		)
		require.NoError(tb, err, "Failed to generate test token")

		// Create request
		req := httptest.NewRequest("POST", "/api/auth/key", nil)
		req.Host = domain
		req.Header.Set("Authorization", token)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify - should get 401 due to failed strconv.ParseUint
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}
