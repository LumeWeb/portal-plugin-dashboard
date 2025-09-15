package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

func TestOTPGenerate_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		otpSvc := core.GetService[*mocks.MockOTPService](ctx, core.OTP_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Twice()
		otpSvc.On("OTPGenerate", uint(1)).Return("otp-secret", nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("POST", "/api/auth/otp/generate", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.OTPGenerateResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)
		assert.Equal(tb, "otp-secret", response.OTP)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		otpSvc.AssertExpectations(tb)
	})
}

func TestOTPGenerate_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		req := httptest.NewRequest("POST", "/api/auth/otp/generate", nil)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

func TestOTPVerify_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		otpSvc := core.GetService[*mocks.MockOTPService](ctx, core.OTP_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Twice()
		otpSvc.On("OTPEnable", uint(1), "123456").Return(nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		reqBody := dto.OTPVerifyRequest{
			OTP: "123456",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		otpSvc.AssertExpectations(tb)
	})
}

func TestOTPVerify_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create request without JWT token
		reqBody := dto.OTPVerifyRequest{
			OTP: "123456",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

func TestOTPVerify_Failure_InvalidOTP(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		otpSvc := core.GetService[*mocks.MockOTPService](ctx, core.OTP_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Twice()
		otpSvc.On("OTPEnable", uint(1), "123456").Return(core.ErrInvalidOTPCode).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		reqBody := dto.OTPVerifyRequest{
			OTP: "123456",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/verify", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusBadRequest, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		otpSvc.AssertExpectations(tb)
	})
}

func TestOTPValidate_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*mocks.MockAuthService](ctx, core.AUTH_SERVICE)
		otpSvc := core.GetService[*mocks.MockOTPService](ctx, core.OTP_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		authSvc.On("LoginOTP", uint(1), "123456", false).Return("otp-token", nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.Purpose2FA, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		reqBody := dto.OTPValidateRequest{
			OTP: "123456",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/validate", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusFound, w.Code)
		assert.Contains(tb, w.Header().Get("Location"), "/api/auth/complete")

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
		otpSvc.AssertExpectations(tb)
	})
}

func TestOTPDisable_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*mocks.MockAuthService](ctx, core.AUTH_SERVICE)
		otpSvc := core.GetService[*mocks.MockOTPService](ctx, core.OTP_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Twice()
		authSvc.On("ValidLoginByUserID", uint(1), "password").Return(true, mockUser, nil).Once()
		otpSvc.On("OTPDisable", uint(1)).Return(nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		reqBody := dto.OTPDisableRequest{
			Password: "password",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/disable", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
		otpSvc.AssertExpectations(tb)
	})
}

func TestOTPDisable_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create request without JWT token
		reqBody := dto.OTPDisableRequest{
			Password: "password",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/disable", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

func TestOTPDisable_Failure_InvalidPassword(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		authSvc := core.GetService[*mocks.MockAuthService](ctx, core.AUTH_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Twice()
		authSvc.On("ValidLoginByUserID", uint(1), "wrongpassword").Return(false, nil, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request with invalid password
		reqBody := dto.OTPDisableRequest{
			Password: "wrongpassword",
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/auth/otp/disable", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		authSvc.AssertExpectations(tb)
	})
}
