package api

import (
	"net/http"

	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/queryutil"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	"go.uber.org/zap"
)

func (a *API) convertWorkflowInstanceToOperationListItem(instance *core.WorkflowInstance, status *core.WorkflowStatus) *dto.OperationListItem {
	// Extract error message if workflow failed
	var errorMsg *string
	if status.Status == models.RequestStatusFailed && status.Message != "" {
		errorMsg = &status.Message
	}

	// Create CID pointer if hash exists
	var cidPtr *cid.Cid
	if instance.Request.Hash != nil {
		cidVal := cid.NewCidV1(instance.Request.CIDType, instance.Request.Hash)
		cidPtr = &cidVal
	}

	// Create step pointers
	totalSteps := int64(status.TotalSteps)
	currentStep := int64(status.CurrentStep)

	return &dto.OperationListItem{
		ID:                    uint64(instance.Request.ID),
		Operation:             instance.Request.Operation,
		Protocol:              instance.Request.Protocol,
		Status:                status.Status,
		StatusMessage:         status.Message,
		ProgressPercent:       status.Progress,
		StartedAt:             instance.Request.CreatedAt,
		UpdatedAt:             instance.Request.UpdatedAt,
		EstimatedCompletionAt: nil,
		CID:                   cidPtr,
		TotalSteps:            &totalSteps,
		CurrentStep:           &currentStep,
		Error:                 errorMsg,
	}
}

func (a *API) convertWorkflowInstanceToOperationDetailResponse(instance *core.WorkflowInstance, status *core.WorkflowStatus) *dto.OperationDetailResponse {
	// Extract error message if workflow failed
	var errorMsg *string
	if status.Status == models.RequestStatusFailed && status.Message != "" {
		errorMsg = &status.Message
	}

	// Create CID pointer if hash exists
	var cidPtr *cid.Cid
	if instance.Request.Hash != nil {
		cidVal := cid.NewCidV1(instance.Request.CIDType, instance.Request.Hash)
		cidPtr = &cidVal
	}

	// Create step pointers if values are meaningful
	var totalSteps, currentStep *int64
	if status.TotalSteps > 0 {
		val := int64(status.TotalSteps)
		totalSteps = &val
	}
	if status.CurrentStep >= 0 {
		val := int64(status.CurrentStep)
		currentStep = &val
	}

	return &dto.OperationDetailResponse{
		ID:                    uint64(instance.Request.ID),
		Operation:             instance.Request.Operation,
		Protocol:              instance.Request.Protocol,
		Status:                status.Status,
		StatusMessage:         status.Message,
		ProgressPercent:       status.Progress,
		StartedAt:             instance.Request.CreatedAt,
		UpdatedAt:             instance.Request.UpdatedAt,
		EstimatedCompletionAt: nil, // Could calculate from workflow if needed
		CID:                   cidPtr,
		TotalSteps:            totalSteps,
		CurrentStep:           currentStep,
		Error:                 errorMsg, // Extract error from workflow status message
	}
}

func (a *API) buildOperationRoutes(authMw echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	schemaProvider := queryutil.NewSchemaProvider()
	operationSchema := schemaProvider.ForType(dto.OperationListItem{})

	return []router.Route{
		router.NewRoute(http.MethodGet, "/api/operations", a.listOperations,
			router.WithSwaggerOptions(
				router.WithSummary("List Operations"),
				router.WithDescription("Retrieve a list of operations, with filtering, searching, and pagination support."),
				router.WithQueryParam("search", "Search term for filename or other relevant operation data", ""),
				router.WithPaginationParams(),
				router.WithSortParams(operationSchema.SortableFields()),
				//  TODO: Fix panic on processing schemas with pointers?
				//	router.WithFilterParamsFromSchema(operationSchema),
				router.WithSuccessResponse(http.StatusOK, "A list of operations",
					router.WithJSONContent(queryutil.Response[*dto.OperationListItem]{}),
					router.WithTotalCountHeader(),
				),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodGet, "/api/operations/filters", a.getOperationFilters,
			router.WithSwaggerOptions(
				router.WithSummary("Get Operation Filters"),
				router.WithDescription("Retrieves distinct filter values for operations (statuses, operations, protocols)"),
				router.WithSuccessResponse(http.StatusOK, "Distinct filter values for operations",
					router.WithJSONContent(dto.OperationFiltersResponse{}),
				),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodGet, "/api/operations/:id", a.getOperation,
			router.WithSwaggerOptions(
				router.WithSummary("Get Operation Details"),
				router.WithDescription("Retrieve detailed information for a specific operation by its ID."),
				router.WithPathParam("id", "The unique identifier of the operation", uint64(0)),
				router.WithSuccessResponse(http.StatusOK, "Detailed information about the operation",
					router.WithJSONContent(dto.OperationDetailResponse{}),
				),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	}
}

func (a *API) listOperations(c echo.Context) error {
	ctx := httputil.Context(c)
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	// Use workflow service instead of request service
	workflowSvc := core.GetService[core.WorkflowService](a.ctx, core.WORKFLOW_SERVICE)

	return queryutilHttp.ProcessListRequest(
		c.Response(),
		c.Request(),
		"operations",
		func(filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*dto.OperationListItem, int64, error) {
			reqCtx := ctx.Request().Context()
			// Use ListWorkflowInstances instead of GetRequests
			instances, total, err := workflowSvc.ListWorkflowInstances(reqCtx, userID, filters, sorts, pagination)
			if err != nil {
				return nil, 0, err
			}

			items := make([]*dto.OperationListItem, 0, len(instances))
			for _, instance := range instances {
				// Get workflow status for progress information
				status, err := workflowSvc.GetWorkflowStatus(reqCtx, instance.Request.ID)
				if err != nil {
					// If we can't get status, use the request status
					status = &core.WorkflowStatus{
						Status:   instance.Request.Status,
						Progress: 0,
					}
				}

				item := &dto.OperationListItem{}
				err = item.FromModel(a.convertWorkflowInstanceToOperationListItem(instance, status))
				if err != nil {
					// If we can't convert the model, log the error and skip this item
					a.ctx.Logger().Error("failed to convert operation item", zap.Error(err), zap.Uint("request_id", instance.Request.ID))
					continue
				}
				items = append(items, item)
			}

			return items, total, nil
		},
		func(item *dto.OperationListItem) dto.OperationListItem {
			return *item
		},
	)
}

func (a *API) getOperation(c echo.Context) error {
	ctx := httputil.Context(c)
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var paramDto dto.OperationRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.OperationRequest, *dto.OperationRequest](ctx, &paramDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	// Use workflow service instead of request service
	workflowSvc := core.GetService[core.WorkflowService](a.ctx, core.WORKFLOW_SERVICE)

	// Get workflow instance and verify ownership
	instance, err := workflowSvc.GetWorkflowInstance(ctx.Request().Context(), userID, uint(paramDto.ID))
	if err != nil {
		return ctx.Error(err, http.StatusNotFound)
	}

	// instance should be non-nil here; if not, treat as not found upstream

	// Get workflow status for detailed progress information
	status, err := workflowSvc.GetWorkflowStatus(ctx.Request().Context(), instance.Request.ID)
	if err != nil {
		// If we can't get status, use default values
		status = &core.WorkflowStatus{
			Progress: 0,
		}
	}

	response := a.convertWorkflowInstanceToOperationDetailResponse(instance, status)
	var responseDto dto.OperationDetailResponse
	return httputil.EncodeResponse(ctx, response, &responseDto)
}

func (a *API) getOperationFilters(c echo.Context) error {
	ctx := httputil.Context(c)
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	// Use workflow service instead of request service
	workflowSvc := core.GetService[core.WorkflowService](a.ctx, core.WORKFLOW_SERVICE)

	// Get distinct filter values
	filters, err := workflowSvc.ListDistinctWorkflowFilters(ctx.Request().Context(), userID, nil)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	response := &dto.OperationFiltersResponse{}

	return httputil.EncodeResponse(ctx, filters, response)
}

func (a *API) wsOperations(c echo.Context) error {
	/*	ctx := httputil.Context(c)
		userID, ok := a.getUser(ctx)
		if !ok {
			return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		}

		// Upgrade connection to WebSocket
		ws, err := ctx.UpgradeWebsocket()
		if err != nil {
			return ctx.Error(err, http.StatusInternalServerError)
		}
		defer ws.Close()

		// Register client with user ID
		client := &OperationClient{
			hub:    a.operationHub,
			conn:   ws,
			send:   make(chan *dto.OperationEvent, 256),
			userID: userID,
		}
		a.operationHub.Register <- client

		// Handle client connection
		go client.WritePump()
		client.ReadPump()*/

	return nil
}
