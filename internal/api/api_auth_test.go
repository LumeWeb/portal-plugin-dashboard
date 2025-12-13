package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

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

		// Create a valid JWT token for the mock to return
		testToken := CreateTestLoginToken(tb, ctx, "1")

		authSvc.On("LoginPassword", "user@example.com", "password", mock.Anything, false).
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

		// Create a valid JWT token for the mock to return
		testToken := CreateTestLoginToken(tb, ctx, "1")

		authSvc.On("LoginPassword", "user@example.com", "password", mock.Anything, false).
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
