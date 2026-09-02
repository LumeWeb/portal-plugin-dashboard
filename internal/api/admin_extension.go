package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"go.lumeweb.com/queryutil"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SocialAdminExtension extends the admin API with social login provider
// management (full CRUD over SocialProviderConfig rows).
type SocialAdminExtension struct {
	*core.BaseComponent
	providerStore  *provider.ProviderStore
	socialProvider pluginCore.SocialProviderService
}

// NewAdminExtension builds the admin API extension for provider management.
func NewAdminExtension() core.APIExtensionFactory {
	return func() (core.APIExtension, []core.ContextBuilderOption, error) {
		ext := &SocialAdminExtension{}

		return ext, core.ContextOptions(
			core.ContextWithStartupFunc(func(ctx core.Context) error {
				ext.socialProvider = core.GetService[pluginCore.SocialProviderService](ctx, pluginCore.SOCIAL_PROVIDER_SERVICE)
				ext.providerStore = provider.Provider()
				ext.providerStore.SetContext(ctx)
				return nil
			}),
		), nil
	}
}

// TargetAPI returns the API this extension extends.
func (e *SocialAdminExtension) TargetAPI() string {
	return "admin"
}

// Name returns the extension name.
func (e *SocialAdminExtension) Name() string {
	return internal.PLUGIN_NAME
}

// ID returns the extension ID.
func (e *SocialAdminExtension) ID() string {
	return e.Name() + ".social_admin"
}

// Configure adds the social provider admin routes to the admin API.
func (e *SocialAdminExtension) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	routes := e.buildRoutes()
	apiGroup := core.GetAPI(e.TargetAPI()).Subdomain()

	if err := router.RegisterRoutes(gRouter, accessSvc, apiGroup, routes); err != nil {
		e.Logger().Error("Failed to register social admin routes", zap.Error(err))
		return err
	}

	return nil
}

func (e *SocialAdminExtension) buildRoutes() []router.Route {
	providerSchema := queryutil.NewSchemaProvider().ForType(&dto.SocialProviderResponse{})

	return []router.Route{
		e.newRoute(http.MethodGet, "/api/social/providers", e.handleListProviders,
			router.WithSummary("List social login providers"),
			router.WithDescription("Get a paginated list of all configured social login providers. Secrets are never returned."),
			router.WithTags("social", "providers"),
			router.WithSchema(providerSchema),
			router.WithFilterParamsFromSchema(providerSchema),
			router.WithSuccessResponse(http.StatusOK, "List of providers", router.WithJSONContent(&dto.SocialProviderResponse{})),
		),
		e.newRoute(http.MethodPost, "/api/social/providers", e.handleCreateProvider,
			router.WithSummary("Create social login provider"),
			router.WithDescription("Create a new social login provider configuration"),
			router.WithTags("social", "providers"),
			router.WithRequestBody(&dto.SocialProviderRequest{}, "Provider configuration", true),
			router.WithSuccessResponse(http.StatusCreated, "Provider created", router.WithJSONContent(&dto.SocialProviderResponse{})),
		),
		e.newRoute(http.MethodGet, "/api/social/providers/:id", e.handleGetProvider,
			router.WithSummary("Get social login provider"),
			router.WithDescription("Get a single social login provider by ID"),
			router.WithTags("social", "providers"),
			router.WithPathParam("id", "Numeric ID of the provider", ""),
			router.WithSuccessResponse(http.StatusOK, "Provider details", router.WithJSONContent(&dto.SocialProviderResponse{})),
		),
		e.newRoute(http.MethodPut, "/api/social/providers/:id", e.handleUpdateProvider,
			router.WithSummary("Update social login provider"),
			router.WithDescription("Update an existing social login provider"),
			router.WithTags("social", "providers"),
			router.WithPathParam("id", "Numeric ID of the provider", ""),
			router.WithRequestBody(&dto.SocialProviderRequest{}, "Provider configuration", true),
			router.WithSuccessResponse(http.StatusOK, "Provider updated", router.WithJSONContent(&dto.SocialProviderResponse{})),
		),
		e.newRoute(http.MethodDelete, "/api/social/providers/:id", e.handleDeleteProvider,
			router.WithSummary("Delete social login provider"),
			router.WithDescription("Delete a social login provider by ID"),
			router.WithTags("social", "providers"),
			router.WithPathParam("id", "Numeric ID of the provider", ""),
			router.WithoutDefaultSuccessResponse(),
			router.WithSuccessResponse(http.StatusNoContent, "Provider deleted"),
		),
		e.newRoute(http.MethodPost, "/api/social/providers/:id/enable", e.handleEnableProvider,
			router.WithSummary("Enable social login provider"),
			router.WithDescription("Enable a social login provider"),
			router.WithTags("social", "providers"),
			router.WithPathParam("id", "Numeric ID of the provider", ""),
			router.WithSuccessResponse(http.StatusOK, "Provider enabled", router.WithJSONContent(&dto.SocialProviderResponse{})),
		),
		e.newRoute(http.MethodPost, "/api/social/providers/:id/disable", e.handleDisableProvider,
			router.WithSummary("Disable social login provider"),
			router.WithDescription("Disable a social login provider"),
			router.WithTags("social", "providers"),
			router.WithPathParam("id", "Numeric ID of the provider", ""),
			router.WithSuccessResponse(http.StatusOK, "Provider disabled", router.WithJSONContent(&dto.SocialProviderResponse{})),
		),
	}
}

func (e *SocialAdminExtension) buildMiddlewares() []echo.MiddlewareFunc {
	authMw := middleware.AuthMiddleware(e.Context(), middleware.WithAuthPurpose(jwt.PurposeLogin))
	accessMw := middleware.AccessMiddleware(e.Context())
	return []echo.MiddlewareFunc{authMw, accessMw}
}

func (e *SocialAdminExtension) newRoute(method, path string, handler echo.HandlerFunc, opts ...router.SwaggerOption) router.Route {
	return router.NewRoute(method, path, handler,
		router.WithAccess(core.ACCESS_ADMIN_ROLE),
		router.WithMiddlewares(e.buildMiddlewares()...),
		router.WithSwaggerOptions(opts...),
	)
}

func (e *SocialAdminExtension) handleListProviders(c echo.Context) error {
	ctx := httputil.Context(c)
	reqCtx := ctx.Context.Request().Context()

	return queryutilHttp.ProcessListRequest(
		c.Response(),
		c.Request(),
		"social_providers",
		func(filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*pluginDb.SocialProviderConfig, int64, error) {
			return e.socialProvider.List(reqCtx, filters, sorts, pagination)
		},
		func(config *pluginDb.SocialProviderConfig) dto.SocialProviderResponse {
			var resp dto.SocialProviderResponse
			resp.FromModel(config)
			return resp
		},
	)
}

func (e *SocialAdminExtension) handleCreateProvider(c echo.Context) error {
	ctx := httputil.Context(c)
	reqCtx := ctx.Context.Request().Context()

	var req dto.SocialProviderRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.SocialProviderRequest, *dto.SocialProviderRequest](ctx, &req)
	if !ok {
		return nil
	}

	if req.ProviderID == "" || req.ClientID == "" || req.ClientSecret == "" {
		return ctx.Error(errors.New("provider_id, client_id and client_secret are required"), http.StatusBadRequest)
	}

	config := &pluginDb.SocialProviderConfig{
		ProviderID:   req.ProviderID,
		DisplayName:  req.DisplayName,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		AuthURL:      req.AuthURL,
		TokenURL:     req.TokenURL,
		UserURL:      req.UserURL,
		UserIDKey:    req.UserIDKey,
		UserEmailKey: req.UserEmailKey,
		UserNameKey:  req.UserNameKey,
		Enabled:      boolPtrValue(req.Enabled, false),
		OrderIndex:   intPtrValue(req.OrderIndex, 0),
	}
	if err := config.SetScopes(req.Scopes); err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	if err := e.socialProvider.Create(reqCtx, config); err != nil {
		if db.IsDuplicateKeyError(err) {
			return ctx.Error(errors.New("provider_id already exists"), http.StatusConflict)
		}
		e.Logger().Error("failed to create social provider", zap.Error(err))
		return ctx.Error(err, http.StatusInternalServerError)
	}

	e.refreshProviderStore(reqCtx)

	var resp dto.SocialProviderResponse
	resp.FromModel(config)
	return ctx.JSON(http.StatusCreated, resp)
}

func (e *SocialAdminExtension) handleGetProvider(c echo.Context) error {
	ctx := httputil.Context(c)
	reqCtx := ctx.Context.Request().Context()

	id, err := parseIDParam(c)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	config, err := e.socialProvider.Get(reqCtx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.Error(errors.New("provider not found"), http.StatusNotFound)
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	var resp dto.SocialProviderResponse
	resp.FromModel(config)
	return ctx.JSON(http.StatusOK, resp)
}

func (e *SocialAdminExtension) handleUpdateProvider(c echo.Context) error {
	ctx := httputil.Context(c)
	reqCtx := ctx.Context.Request().Context()

	id, err := parseIDParam(c)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	var req dto.SocialProviderRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.SocialProviderRequest, *dto.SocialProviderRequest](ctx, &req)
	if !ok {
		return nil
	}

	config, err := e.socialProvider.Get(reqCtx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.Error(errors.New("provider not found"), http.StatusNotFound)
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if req.ProviderID != "" {
		config.ProviderID = req.ProviderID
	}
	if req.DisplayName != "" {
		config.DisplayName = req.DisplayName
	}
	if req.ClientID != "" {
		config.ClientID = req.ClientID
	}
	if req.ClientSecret != "" {
		config.ClientSecret = req.ClientSecret
	}
	if req.AuthURL != "" {
		config.AuthURL = req.AuthURL
	}
	if req.TokenURL != "" {
		config.TokenURL = req.TokenURL
	}
	if req.UserURL != "" {
		config.UserURL = req.UserURL
	}
	if req.UserIDKey != "" {
		config.UserIDKey = req.UserIDKey
	}
	if req.UserEmailKey != "" {
		config.UserEmailKey = req.UserEmailKey
	}
	if req.UserNameKey != "" {
		config.UserNameKey = req.UserNameKey
	}
	if req.Enabled != nil {
		config.Enabled = *req.Enabled
	}
	if req.OrderIndex != nil {
		config.OrderIndex = *req.OrderIndex
	}
	if req.Scopes != nil {
		if err := config.SetScopes(req.Scopes); err != nil {
			return ctx.Error(err, http.StatusBadRequest)
		}
	}

	if err := e.socialProvider.Update(reqCtx, config); err != nil {
		if db.IsDuplicateKeyError(err) {
			return ctx.Error(errors.New("provider_id already exists"), http.StatusConflict)
		}
		e.Logger().Error("failed to update social provider", zap.Error(err))
		return ctx.Error(err, http.StatusInternalServerError)
	}

	e.refreshProviderStore(reqCtx)

	var resp dto.SocialProviderResponse
	resp.FromModel(config)
	return ctx.JSON(http.StatusOK, resp)
}

func (e *SocialAdminExtension) handleDeleteProvider(c echo.Context) error {
	ctx := httputil.Context(c)
	reqCtx := ctx.Context.Request().Context()

	id, err := parseIDParam(c)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	// Hard-delete: provider config is ephemeral admin state with no audit or
	// restore value. A soft-deleted row keeps holding the provider_id unique
	// slot, so re-creating a deleted provider (a normal admin workflow) would
	// fail forever; the provider store is reloaded from the DB after every
	// mutation anyway.
	rows, err := e.socialProvider.Delete(reqCtx, id)
	if err != nil {
		e.Logger().Error("failed to delete social provider", zap.Error(err))
		return ctx.Error(err, http.StatusInternalServerError)
	}
	if rows == 0 {
		return ctx.Error(errors.New("provider not found"), http.StatusNotFound)
	}

	e.refreshProviderStore(reqCtx)
	return c.NoContent(http.StatusNoContent)
}

func (e *SocialAdminExtension) handleEnableProvider(c echo.Context) error {
	return e.setProviderEnabled(c, true)
}

func (e *SocialAdminExtension) handleDisableProvider(c echo.Context) error {
	return e.setProviderEnabled(c, false)
}

func (e *SocialAdminExtension) setProviderEnabled(c echo.Context, enabled bool) error {
	ctx := httputil.Context(c)
	reqCtx := ctx.Context.Request().Context()

	id, err := parseIDParam(c)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	config, err := e.socialProvider.Get(reqCtx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.Error(errors.New("provider not found"), http.StatusNotFound)
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	config.Enabled = enabled
	if err := e.socialProvider.Update(reqCtx, config); err != nil {
		e.Logger().Error("failed to set social provider enabled state", zap.Error(err))
		return ctx.Error(err, http.StatusInternalServerError)
	}

	e.refreshProviderStore(reqCtx)

	var resp dto.SocialProviderResponse
	resp.FromModel(config)
	return ctx.JSON(http.StatusOK, resp)
}

// refreshProviderStore reloads the in-memory provider cache so provider
// changes take effect immediately.
func (e *SocialAdminExtension) refreshProviderStore(_ context.Context) {
	if err := e.providerStore.LoadFromDB(e.DB()); err != nil {
		e.Logger().Error("failed to reload social providers", zap.Error(err))
	}
}

func parseIDParam(c echo.Context) (uint, error) {
	v := c.Param("id")
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid id: %w", err)
	}
	return uint(id), nil
}

func boolPtrValue(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func intPtrValue(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}
