package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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
	"go.lumeweb.com/queryutil"
	"go.lumeweb.com/queryutil/filter"
	"gorm.io/gorm"
)

func TestCreateAPIKey_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		// AccountExists is called once by auth middleware
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Once()
		mockAPIKey := &pluginDb.APIKey{
			UUID: types.NewBinUUID(),
			Name: "test-key",
			JWT:  "generated-jwt-token",
		}
		// createAPIKey now routes through the service issuance method, which
		// signs the JWT and returns the one-time IssuedAPIKey result.
		apiKeySvc.EXPECT().IssueAPIKey(mock.Anything, uint(1), "test-key", mock.Anything).
			Return(&pluginCore.IssuedAPIKey{
				ID:        uint(1),
				Token:     "generated-jwt-token",
				ExpiresAt: time.Now().Add(time.Hour * 24 * 30),
				UUID:      mockAPIKey.UUID.ToUUID(),
				Name:      "test-key",
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
		// X-Total-Count header is not set for create operations

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

func TestCreateAPIKey_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
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
		// Response body might be empty for unauthorized requests

		// Verify mock expectations - no AccountExists should be called for unauthorized requests
		userSvc.AssertExpectations(tb)
	})
}

func TestCreateAPIKey_Failure_InvalidInput(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock expectations
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Once()

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

func TestGetAPIKeysRejectsUnsafeQueriesBeforeServiceCall(t *testing.T) {
	for _, query := range []url.Values{
		{"filters[user_id][eq]": {"2"}},
		{"filters[or][0][name][eq]": {"a"}, "filters[or][1][user_id][eq]": {"2"}},
		{"_sort": {"(SELECT 1)"}},
		{"filters[name][gt]": {"123"}},
	} {
		t.Run(query.Encode(), func(t *testing.T) {
			coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
				userSvc := coreTesting.GetMockUserService(ctx)
				apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
				userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, &models.User{Model: gorm.Model{ID: 1}}, nil).Once()
				token := CreateTestLoginToken(tb, ctx, "1")
				domain := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, false)
				req := httptest.NewRequest(http.MethodGet, "/api/account/keys?"+query.Encode(), nil)
				req.Host = domain
				req.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				ctx.Router().ServeHTTP(w, req)
				require.Equal(tb, http.StatusBadRequest, w.Code, w.Body.String())
				apiKeySvc.AssertNotCalled(tb, "GetAPIKeys", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			})
		})
	}
}

func TestGetAPIKeysPreservesNumericOnlyName(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		userSvc := coreTesting.GetMockUserService(ctx)
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, &models.User{Model: gorm.Model{ID: 1}}, nil).Once()
		apiKeySvc.EXPECT().GetAPIKeys(mock.Anything, uint(1), mock.MatchedBy(func(filters []queryutil.CrudFilter) bool {
			if len(filters) != 1 {
				return false
			}
			node, ok := filters[0].(*filter.LogicalFilter)
			return ok && node.Field() == "name" && node.Operator() == filter.OpEq && node.Value() == "00123"
		}), mock.Anything, mock.Anything).Return([]*pluginDb.APIKey{}, int64(0), nil).Once()
		token := CreateTestLoginToken(tb, ctx, "1")
		domain := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, false)
		req := httptest.NewRequest(http.MethodGet, "/api/account/keys?filters%5Bname%5D%5Beq%5D=00123", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		ctx.Router().ServeHTTP(w, req)
		require.Equal(tb, http.StatusOK, w.Code, w.Body.String())
	})
}

func TestGetAPIKeysPreservesNumericOnlySearch(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		userSvc := coreTesting.GetMockUserService(ctx)
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, &models.User{Model: gorm.Model{ID: 1}}, nil).Once()
		apiKeySvc.EXPECT().GetAPIKeys(mock.Anything, uint(1), mock.MatchedBy(func(filters []queryutil.CrudFilter) bool {
			if len(filters) != 1 {
				return false
			}
			node, ok := filters[0].(*filter.LogicalFilter)
			return ok && node.Field() == "q" && node.Operator() == filter.OpContains && node.Value() == "12345"
		}), mock.Anything, mock.Anything).Return([]*pluginDb.APIKey{}, int64(0), nil).Once()
		token := CreateTestLoginToken(tb, ctx, "1")
		domain := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, false)
		req := httptest.NewRequest(http.MethodGet, "/api/account/keys?filters%5Bq%5D%5Beq%5D=12345", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		ctx.Router().ServeHTTP(w, req)
		require.Equal(tb, http.StatusOK, w.Code, w.Body.String())
	})
}

func TestGetAPIKeys_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
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

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Once()
		apiKeySvc.EXPECT().GetAPIKeys(mock.Anything, uint(1), mock.Anything, mock.Anything, mock.Anything).
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

func TestGetAPIKeys_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
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
		// Response body might be empty for unauthorized requests

		// Verify mock expectations - no AccountExists should be called for unauthorized requests
		userSvc.AssertExpectations(tb)
	})
}

func TestDeleteAPIKey_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
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

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Once()
		apiKeySvc.EXPECT().DeleteAPIKey(mock.Anything, uint(1), keyUUID.ToUUID()).Return(nil).Once()

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

func TestDeleteAPIKey_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
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
		// Response body might be empty for unauthorized requests

		// Verify mock expectations - no AccountExists should be called for unauthorized requests
		userSvc.AssertExpectations(tb)
	})
}

func TestDeleteAPIKey_Failure_NotFound(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := coreTesting.GetMockUserService(ctx)
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
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

		userSvc.EXPECT().AccountExists(mock.Anything, uint(1)).Return(true, mockUser, nil).Once()
		apiKeySvc.EXPECT().DeleteAPIKey(mock.Anything, uint(1), keyUUID.ToUUID()).Return(gorm.ErrRecordNotFound).Once()

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
