package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/service"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.lumeweb.com/portal/db/types"
)

func TestMain(m *testing.M) {
	// Use the new framework's TestMain helper to set up the shared environment.
	// We use WithOptions because these tests do not require a real database.
	coreTesting.WithOptions(m,
		// Configure the domain for the API
		coreTesting.WithConfigValue("core.domain", "example.com"),
		// Register the Dashboard API using the helper
		coreTesting.NewAPIRegistrationOption(internal.PLUGIN_NAME, NewAPI),
		coreTesting.WithMockAPIConfig(internal.PLUGIN_NAME, &pluginConfig.APIConfig{
			Subdomain: "account",
		}),
		// Explicitly add the APIKeyService mock, as it's not in the core defaults
		coreTesting.WithMockServiceFactory(service.API_KEY_SERVICE, service.NewMockAPIKeyService),
	)
}

// TestLogin_Success tests a successful user login without OTP.
func TestLogin_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*mocks.MockAuthService](ctx, core.AUTH_SERVICE)
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

		userSvc.On("EmailExists", "user@example.com").Return(true, mockUser, nil).Once()
		authSvc.On("LoginPassword", "user@example.com", "password", mock.Anything, false).
			Return("testtoken", mockUser, nil).Once()

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

// TestLogin_OTPRequired tests a successful user login requiring OTP.
func TestLogin_OTPRequired(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*mocks.MockAuthService](ctx, core.AUTH_SERVICE)
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

		userSvc.On("EmailExists", "user@example.com").Return(true, mockUser, nil).Once()
		authSvc.On("LoginPassword", "user@example.com", "password", mock.Anything, false).
			Return("testtoken", mockUser, nil).Once()

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
		assert.Equal(tb, "testtoken", response.Token)
		assert.True(tb, response.Otp)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}

// TestLogin_InvalidCredentials tests login with invalid credentials.
func TestLogin_InvalidCredentials(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		userSvc.On("EmailExists", "user@example.com").Return(false, nil, nil).Once()

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

// TestRegister_Success tests successful user registration.
func TestRegister_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)
		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "newuser@example.com",
		}

		userSvc.On("CreateAccount", "newuser@example.com", "password", true).
			Return(mockUser, nil).Once()
		userSvc.On("UpdateAccountName", uint(1), "John", "Doe").
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

// TestCreateAPIKey_Success tests successful API key creation.
func TestCreateAPIKey_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		apiKeySvc := core.GetService[*service.MockAPIKeyService](ctx, service.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		mockAPIKey := &pluginDb.APIKey{
			UUID: types.NewBinUUID(),
			Name: "test-key",
			JWT:  "generated-jwt-token",
		}
		apiKeySvc.On("CreateAPIKey", uint(1), "test-key").
			Return(&pluginDb.APIKey{
				UUID: mockAPIKey.UUID,
				Name: "test-key",
				JWT:  "generated-jwt-token",
			}, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		reqBody := dto.APIKeyCreateRequest{
			Name: "test-key",
		}

		body, _ := json.Marshal(reqBody)

		// Use the full API path including the subdomain
		req := httptest.NewRequest("POST", "/api/account/keys", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.CreateAPIKeyResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)
		assert.NotEmpty(tb, response.Token) // Just verify token is generated
		assert.Equal(tb, mockAPIKey.UUID, response.UUID)
		assert.Equal(tb, "test-key", response.Name)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		apiKeySvc.AssertExpectations(tb)
	})
}

// TestCreateAPIKey_Failure_Unauthorized tests API key creation failure due to missing authentication.
func TestCreateAPIKey_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create request without JWT token
		reqBody := dto.APIKeyCreateRequest{
			Name: "test-key",
		}

		body, _ := json.Marshal(reqBody)

		// Use the full API path including the subdomain
		req := httptest.NewRequest("POST", "/api/account/keys", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

// TestCreateAPIKey_Failure_InvalidInput tests API key creation failure due to invalid input.
func TestCreateAPIKey_Failure_InvalidInput(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request with invalid input (empty name)
		reqBody := dto.APIKeyCreateRequest{
			Name: "",
		}

		body, _ := json.Marshal(reqBody)

		// Use the full API path including the subdomain
		req := httptest.NewRequest("POST", "/api/account/keys", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnprocessableEntity, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
	})
}

// TestGetAPIKeys_Success tests successful retrieval of API keys.
func TestGetAPIKeys_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		apiKeySvc := core.GetService[*service.MockAPIKeyService](ctx, service.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockKeys := []*pluginDb.APIKey{
			{
				Model: gorm.Model{ID: 1},
				Name:  "key1",
				UUID:  types.NewBinUUID(),
			},
			{
				Model: gorm.Model{ID: 2},
				Name:  "key2",
				UUID:  types.NewBinUUID(),
			},
		}

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		apiKeySvc.On("GetAPIKeys", uint(1), mock.Anything, mock.Anything, mock.Anything).
			Return(mockKeys, int64(2), nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/account/keys", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response struct {
			Data  []dto.APIKeyResponse `json:"data"`
			Total int64                `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)

		assert.Equal(tb, int64(2), response.Total)
		assert.Len(tb, response.Data, 2)
		assert.Equal(tb, "key1", response.Data[0].Name)
		assert.Equal(tb, "key2", response.Data[1].Name)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		apiKeySvc.AssertExpectations(tb)
	})
}

// TestGetAPIKeys_Failure_Unauthorized tests retrieval of API keys failure due to missing authentication.
func TestGetAPIKeys_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		req := httptest.NewRequest("GET", "/api/account/keys", nil)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

// TestDeleteAPIKey_Success tests successful deletion of an API key.
func TestDeleteAPIKey_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		apiKeySvc := core.GetService[*service.MockAPIKeyService](ctx, service.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		keyUUID := types.NewBinUUID()

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		apiKeySvc.On("DeleteAPIKey", uint(1), keyUUID.ToUUID()).Return(nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/account/keys/%s", keyUUID.String()), nil)
		require.NoError(tb, err)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		apiKeySvc.AssertExpectations(tb)
	})
}

// TestDeleteAPIKey_Failure_Unauthorized tests deletion of API key failure due to missing authentication.
func TestDeleteAPIKey_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		keyUUID := types.NewBinUUID()

		// Create request without JWT token
		req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/account/keys/%s", keyUUID.String()), nil)
		require.NoError(tb, err)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

// TestDeleteAPIKey_Failure_NotFound tests deletion of API key failure due to the key not being found.
func TestDeleteAPIKey_Failure_NotFound(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		apiKeySvc := core.GetService[*service.MockAPIKeyService](ctx, service.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		keyUUID := types.NewBinUUID()

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		apiKeySvc.On("DeleteAPIKey", uint(1), keyUUID.ToUUID()).Return(gorm.ErrRecordNotFound).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/account/keys/%s", keyUUID.String()), nil)
		require.NoError(tb, err)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusNotFound, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		apiKeySvc.AssertExpectations(tb)
	})
}
