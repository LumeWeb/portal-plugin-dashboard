package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	swagger "go.lumeweb.com/gswagger"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/service"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/queryutil"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	"gorm.io/gorm"
)

func (a *API) buildAPIKeyRoutes(authMw echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodPost, "/api/account/keys", a.createAPIKey,
			router.WithSwaggerOptions(
				router.WithSummary("Create API Key"),
				router.WithDescription("Creates a new API key for the authenticated user."),
				router.WithRequestBody(dto.APIKeyCreateRequest{}, "API Key name", true),
				router.WithResponseHeaders(http.StatusOK, "API Key created", map[string]swagger.Schema{"application/json": {Value: dto.CreateAPIKeyResponse{}}}, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodGet, "/api/account/keys", a.getAPIKeys,
			router.WithSwaggerOptions(
				router.WithSummary("List API Keys"),
				router.WithDescription("Retrieves a list of API keys for the authenticated user."),
				router.WithPaginationParams(),
				router.WithResponseHeaders(http.StatusOK, "List of API Keys", map[string]swagger.Schema{
					"application/json": {
						Value: queryutil.Response[*dto.APIKeyResponse]{},
					},
				}, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodDelete, "/api/account/keys/:keyID", a.deleteAPIKey,
			router.WithSwaggerOptions(
				router.WithSummary("Delete API Key"),
				router.WithDescription("Deletes a specific API key for the authenticated user."),
				router.WithPathParam("keyID", "The UUID of the API key to delete", uuid.Nil),
				router.WithResponseHeaders(http.StatusOK, "API Key deleted", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	}
}

func (a *API) createAPIKey(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var requestDto dto.APIKeyCreateRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.APIKeyCreateRequest, *dto.APIKeyCreateRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	// Get config provider from core context
	configProvider := adapter.NewFromCore(a.ctx)
	privateKey := configProvider.GetPrivateKey()
	domain := configProvider.GetDomain()

	// Create API key record
	apiKey, err := a.apiKey.CreateAPIKey(user, requestDto.Name)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	// Generate JWT for the API key
	apiKeyJWT, err := jwt.CreateToken(
		privateKey,
		domain,
		fmt.Sprintf("%d", user),
		service.PurposeAPI,
		time.Hour*24*30, // 30 day expiry
		jwt.WithClaims(&jwt.RegisteredClaims{
			ID: apiKey.UUID.String(),
		}),
	)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	apiKey.JWT = apiKeyJWT

	var responseDto dto.CreateAPIKeyResponse
	return httputil.EncodeResponse(ctx, apiKey, &responseDto)
}

func (a *API) getAPIKeys(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	return queryutilHttp.ProcessListRequest(
		c.Response(),
		c.Request(),
		"api_keys",
		func(filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*pluginDb.APIKey, int64, error) {
			return a.apiKey.GetAPIKeys(user, filters, sorts, pagination)
		},
		func(key *pluginDb.APIKey) dto.APIKeyResponse {
			var resp dto.APIKeyResponse
			_ = resp.FromModel(key)
			return resp
		},
	)
}

func (a *API) deleteAPIKey(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	keyID, err := uuid.Parse(c.Param("keyID"))
	if err != nil {
		return ctx.Error(fmt.Errorf("invalid key ID"), http.StatusBadRequest)
	}

	err = a.apiKey.DeleteAPIKey(user, keyID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.Error(err, http.StatusNotFound)
		}
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) authWithAPIKey(c echo.Context) error {
	ctx := httputil.Context(c)

	token, ok := a.getAuthToken(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	// Decode the token once
	decodedToken, err := jwt.DecodeToken(token, &jwt.RegisteredClaims{})
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusUnauthorized)
	}

	claims, ok := decodedToken.(*jwt.RegisteredClaims)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, errors.New("invalid token claims")), http.StatusUnauthorized)
	}

	// Extract user ID from the subject claim
	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusUnauthorized)
	}

	// Extract key ID from the token ID claim
	keyID, err := uuid.Parse(claims.ID)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusUnauthorized)
	}

	// Validate the API key using the parsed user ID and key ID
	validatedKey, err := a.apiKey.ValidateAPIKey(uint(userID), keyID)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusUnauthorized)
	}

	// Login with the validated user ID
	_jwt, err := a.auth.LoginID(validatedKey.UserID, ctx.RealIP(), false)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	responseModel := &dto.LoginResponse{
		Token: _jwt,
	}
	var responseDto dto.LoginResponse
	return httputil.EncodeResponse(ctx, responseModel, &responseDto)
}
