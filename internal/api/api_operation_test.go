package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestListOperations_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Generate valid CIDs for testing
		hash1, err := multihash.Sum([]byte("testhash1"), multihash.SHA2_256, -1)
		require.NoError(tb, err)
		cid1 := cid.NewCidV1(cid.DagProtobuf, hash1)

		hash2, err := multihash.Sum([]byte("testhash2"), multihash.SHA2_256, -1)
		require.NoError(tb, err)
		cid2 := cid.NewCidV1(cid.DagProtobuf, hash2)

		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		workflowSvc := core.GetService[*mocks.MockWorkflowService](ctx, core.WORKFLOW_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		mockInstances := []*core.WorkflowInstance{
			{
				Request: &models.Request{
					Model: gorm.Model{ID: 1,
						CreatedAt: time.Now().Add(-time.Hour),
						UpdatedAt: time.Now().Add(-time.Minute),
					},
					Operation: "upload",
					Protocol:  "s3",
					Status:    models.RequestStatusCompleted,
					CIDType:   cid.DagProtobuf,
					Hash:      cid1.Hash(),
				},
				Status: &core.WorkflowStatus{
					WorkflowName: "upload",
					CurrentStep:  2,
					TotalSteps:   3,
					Status:       models.RequestStatusCompleted,
					Progress:     66.67,
					Message:      "Upload completed",
				},
			},
			{
				Request: &models.Request{
					Model: gorm.Model{ID: 2,
						CreatedAt: time.Now().Add(-time.Hour * 2),
						UpdatedAt: time.Now().Add(-time.Minute * 5),
					},
					Operation: "pin",
					Protocol:  "ipfs",
					Status:    models.RequestStatusPending,
					CIDType:   cid.DagProtobuf,
					Hash:      cid2.Hash(),
				},
				Status: &core.WorkflowStatus{
					WorkflowName: "pin",
					CurrentStep:  0,
					TotalSteps:   2,
					Status:       models.RequestStatusPending,
					Progress:     0,
					Message:      "Starting pin process",
				},
			},
		}

		// Mock expectations
		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		workflowSvc.On("ListWorkflowInstances", mock.Anything, uint(1), mock.Anything, mock.Anything, mock.Anything).
			Return(mockInstances, int64(2), nil).Once()
		workflowSvc.On("GetWorkflowStatus", mock.Anything, uint(1)).
			Return(mockInstances[0].Status, nil).Once()
		workflowSvc.On("GetWorkflowStatus", mock.Anything, uint(2)).
			Return(mockInstances[1].Status, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/operations", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response struct {
			Data  []dto.OperationListItem `json:"data"`
			Total int64                   `json:"total"`
		}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)

		assert.Equal(tb, int64(2), response.Total)
		assert.Len(tb, response.Data, 2)

		// Verify first operation
		op1 := response.Data[0]
		assert.Equal(tb, uint64(1), op1.ID)
		assert.Equal(tb, "upload", op1.Operation)
		assert.Equal(tb, "s3", op1.Protocol)
		assert.Equal(tb, models.RequestStatusCompleted, op1.Status)
		assert.Equal(tb, "Upload completed", op1.StatusMessage)
		assert.InDelta(tb, float64(66.67), op1.ProgressPercent, 0.005)
		assert.Equal(tb, int64(3), *op1.TotalSteps)
		assert.Equal(tb, int64(2), *op1.CurrentStep)

		// Verify second operation
		op2 := response.Data[1]
		assert.Equal(tb, uint64(2), op2.ID)
		assert.Equal(tb, "pin", op2.Operation)
		assert.Equal(tb, "ipfs", op2.Protocol)
		assert.Equal(tb, models.RequestStatusPending, op2.Status)
		assert.Equal(tb, "Starting pin process", op2.StatusMessage)
		assert.Equal(tb, float64(0), op2.ProgressPercent)
		assert.Equal(tb, int64(2), *op2.TotalSteps)
		assert.Equal(tb, int64(0), *op2.CurrentStep)

		// Verify CID - use the same CID that was created in the test
		assert.Equal(tb, &cid1, op1.CID)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		workflowSvc.AssertExpectations(tb)
	})
}

func TestGetOperationFilters_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		workflowSvc := core.GetService[*mocks.MockWorkflowService](ctx, core.WORKFLOW_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		mockFilters := map[string][]string{
			"status":    {"completed", "pending", "failed"},
			"operation": {"upload", "pin"},
			"protocol":  {"s3", "ipfs"},
		}

		// Mock expectations
		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		workflowSvc.On("ListDistinctWorkflowFilters", mock.Anything, uint(1), mock.Anything).
			Return(mockFilters, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/operations/filters", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.OperationFiltersResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)

		// Verify we have distinct values
		assert.Len(tb, response.Statuses, 3)   // completed, pending, failed
		assert.Len(tb, response.Operations, 2) // upload, pin
		assert.Len(tb, response.Protocols, 2)  // s3, ipfs

		// Verify content includes expected values
		expectedStatuses := []models.RequestStatusType{
			models.RequestStatusCompleted,
			models.RequestStatusPending,
			models.RequestStatusFailed,
		}
		for _, status := range expectedStatuses {
			assert.Contains(tb, response.Statuses, status)
		}

		expectedOperations := []string{"upload", "pin"}
		for _, operation := range expectedOperations {
			assert.Contains(tb, response.Operations, operation)
		}

		expectedProtocols := []string{"s3", "ipfs"}
		for _, protocol := range expectedProtocols {
			assert.Contains(tb, response.Protocols, protocol)
		}

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		workflowSvc.AssertExpectations(tb)
	})
}

func TestGetOperationFilters_EmptyResult(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		workflowSvc := core.GetService[*mocks.MockWorkflowService](ctx, core.WORKFLOW_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		// Mock expectations - empty filters map
		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		workflowSvc.On("ListDistinctWorkflowFilters", mock.Anything, uint(1), mock.Anything).
			Return(map[string][]string{}, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/operations/filters", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.OperationFiltersResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)

		// Verify empty results
		assert.Len(tb, response.Statuses, 0)
		assert.Len(tb, response.Operations, 0)
		assert.Len(tb, response.Protocols, 0)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		workflowSvc.AssertExpectations(tb)
	})
}

func TestGetOperationFilters_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		req := httptest.NewRequest("GET", "/api/operations/filters", nil)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

func TestGetOperationFilters_Failure_WorkflowServiceError(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		workflowSvc := core.GetService[*mocks.MockWorkflowService](ctx, core.WORKFLOW_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		// Mock expectations - return error
		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		workflowSvc.On("ListDistinctWorkflowFilters", mock.Anything, uint(1), mock.Anything).
			Return(nil, assert.AnError).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/operations/filters", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusInternalServerError, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		workflowSvc.AssertExpectations(tb)
	})
}

func TestListOperations_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		req := httptest.NewRequest("GET", "/api/operations", nil)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

func TestGetOperation_Success(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Generate valid CID for testing
		hash, err := multihash.Sum([]byte("testhash1"), multihash.SHA2_256, -1)
		require.NoError(tb, err)
		testCID := cid.NewCidV1(cid.DagProtobuf, hash)

		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		workflowSvc := core.GetService[*mocks.MockWorkflowService](ctx, core.WORKFLOW_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		mockInstance := &core.WorkflowInstance{
			Request: &models.Request{
				Model: gorm.Model{ID: 1,
					CreatedAt: time.Now().Add(-time.Hour),
					UpdatedAt: time.Now().Add(-time.Minute)},
				Operation: "upload",
				Protocol:  "s3",
				Status:    models.RequestStatusCompleted,
				CIDType:   cid.DagProtobuf,
				Hash:      testCID.Hash(),
			},
			Status: &core.WorkflowStatus{
				WorkflowName: "upload",
				CurrentStep:  2,
				TotalSteps:   3,
				Status:       models.RequestStatusCompleted,
				Progress:     66.67,
				Message:      "Upload completed",
			},
		}

		// Mock expectations
		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		workflowSvc.On("GetWorkflowInstance", mock.Anything, uint(1), uint(1)).
			Return(mockInstance, nil).Once()
		workflowSvc.On("GetWorkflowStatus", mock.Anything, uint(1)).
			Return(mockInstance.Status, nil).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/operations/1", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusOK, w.Code)

		var response dto.OperationDetailResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(tb, err)

		assert.Equal(tb, uint64(1), response.ID)
		assert.Equal(tb, "upload", response.Operation)
		assert.Equal(tb, "s3", response.Protocol)
		assert.Equal(tb, models.RequestStatusCompleted, response.Status)
		assert.Equal(tb, "Upload completed", response.StatusMessage)
		assert.InDelta(tb, float64(66.67), response.ProgressPercent, 0.005)
		assert.Equal(tb, int64(3), *response.TotalSteps)
		assert.Equal(tb, int64(2), *response.CurrentStep)

		// Verify CID - use the same CID that was created in the test
		assert.Equal(tb, &testCID, response.CID)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		workflowSvc.AssertExpectations(tb)
	})
}

func TestGetOperation_Failure_Unauthorized(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		req := httptest.NewRequest("GET", "/api/operations/1", nil)
		req.Host = domain
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusUnauthorized, w.Code)
	})
}

func TestGetOperation_Failure_NotFound(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		// Retrieve necessary services and router from the context
		userSvc := core.GetService[*mocks.MockUserService](ctx, core.USER_SERVICE)
		workflowSvc := core.GetService[*mocks.MockWorkflowService](ctx, core.WORKFLOW_SERVICE)
		httpSvc := core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE)
		router := ctx.Router()
		domain := httpSvc.APISubdomain(internal.PLUGIN_NAME, false)

		// Mock data
		mockUser := &models.User{
			Model: gorm.Model{ID: 1},
			Email: "test@example.com",
		}

		// Mock expectations
		userSvc.On("AccountExists", uint(1)).Return(true, mockUser, nil).Once()
		workflowSvc.On("GetWorkflowInstance", mock.Anything, uint(1), uint(1)).
			Return(nil, gorm.ErrRecordNotFound).Once()

		// Create valid JWT token using the context's identity
		pk := ctx.Config().Config().Core.Identity.PrivateKey()
		jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, "1", jwt.PurposeLogin, 90*24*time.Hour)
		require.NoError(tb, err, "Failed to generate test JWT")

		req := httptest.NewRequest("GET", "/api/operations/1", nil)
		req.Host = domain
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		// Execute
		router.ServeHTTP(w, req)

		// Verify
		assert.Equal(tb, http.StatusNotFound, w.Code)

		// Verify mock expectations
		userSvc.AssertExpectations(tb)
		workflowSvc.AssertExpectations(tb)
	})
}
