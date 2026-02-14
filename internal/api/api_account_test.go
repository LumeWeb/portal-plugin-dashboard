package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"github.com/samber/lo"
"gorm.io/gorm"
)

func TestUpdateProfile_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model:      gorm.Model{ID: 1},
			Email:      "test@example.com",
			FirstName:  "OldFirst",
			LastName:   "OldLast",
			OTPEnabled: false,
		}

		// Mock expectations
		// AccountExists is called twice - once by auth middleware and once by our handler
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Twice()
		userSvc.EXPECT().UpdateAccountName(mock.Anything, uint(1), "NewFirst", "NewLast").
			Return(nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request
		reqBody := dto.UpdateProfileRequest{
			FirstName: lo.ToPtr("NewFirst"),
			LastName:  lo.ToPtr("NewLast"),
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/account", bytes.NewReader(body))
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
	})
}

func TestUpdateProfile_NoChanges(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*coreTesting.MockUserService](ctx, core.USER_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model:      gorm.Model{ID: 1},
			Email:      "test@example.com",
			FirstName:  "Existing",
			LastName:   "User",
			OTPEnabled: false,
		}

		// Mock expectations
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Twice()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		// Create request with same names as existing user
		reqBody := dto.UpdateProfileRequest{
			FirstName: lo.ToPtr("Existing"),
			LastName:  lo.ToPtr("User"),
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/account", bytes.NewReader(body))
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
	})
}

func TestUpdateProfile_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Create request without JWT token
		reqBody := dto.UpdateProfileRequest{
			FirstName: lo.ToPtr("NewFirst"),
			LastName:  lo.ToPtr("NewLast"),
		}

		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("PATCH", "/api/account", bytes.NewReader(body))
		req.Host = domain
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}
