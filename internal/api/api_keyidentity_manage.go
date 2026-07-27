package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/queryutil"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	router "go.lumeweb.com/portal-router"
	"go.uber.org/zap"
)

func (a *API) buildKeyIdentityManageRoutes(authMw echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		// POST /api/auth/key/connect/challenge — issue challenge for linking a new key
		router.NewRoute(http.MethodPost, "/api/auth/key/connect/challenge", a.keyIdentityConnectChallenge,
			router.WithSwaggerOptions(
				router.WithSummary("Issue Key Identity Connect Challenge"),
				router.WithDescription("Issues a cryptographic challenge for linking a new key identity to the authenticated user's account."),
				router.WithRequestBody(dto.KeyIdentityChallengeRequest{}, "Challenge request", true),
				router.WithSuccessResponse(http.StatusOK, "Challenge issued",
					router.WithJSONContent(dto.KeyIdentityChallengeResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid key type or key format"),
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Not authenticated"),
					router.DefineSwaggerErrorResponse(http.StatusConflict, "Key already linked to another account"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Internal server error"),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		// POST /api/auth/key/connect/verify — verify signed challenge, link key to account
		router.NewRoute(http.MethodPost, "/api/auth/key/connect/verify", a.keyIdentityConnectVerify,
			router.WithSwaggerOptions(
				router.WithSummary("Verify and Connect Key Identity"),
				router.WithDescription("Verifies a signed challenge and links the key identity to the authenticated user's account."),
				router.WithRequestBody(dto.KeyIdentityConnectVerifyRequest{}, "Verification request", true),
				router.WithSuccessResponse(http.StatusOK, "Key identity linked",
					router.WithJSONContent(dto.KeyIdentityConnectVerifyResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid request or verification failed"),
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Not authenticated"),
					router.DefineSwaggerErrorResponse(http.StatusConflict, "Key already linked to another account"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Internal server error"),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		// DELETE /api/auth/key/:type/:key — unlink a key identity
		router.NewRoute(http.MethodDelete, "/api/auth/key/:type/:key", a.keyIdentityDisconnect,
			router.WithSwaggerOptions(
				router.WithSummary("Disconnect Key Identity"),
				router.WithDescription("Unlinks a key identity from the authenticated user's account."),
				router.WithPathParam("type", "The key identity type (e.g., ethereum, solana)", "ethereum"),
				router.WithPathParam("key", "The base58/hex-encoded public key to disconnect", ""),
				router.WithSuccessResponse(http.StatusNoContent, "Key identity removed"),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid key type or key format"),
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Not authenticated"),
					router.DefineSwaggerErrorResponse(http.StatusNotFound, "Key identity not found"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Internal server error"),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		// GET /api/auth/key/identities — list current user's key identities
		router.NewRoute(http.MethodGet, "/api/auth/key/identities", a.keyIdentityList,
			router.WithSwaggerOptions(
				router.WithSummary("List Key Identities"),
				router.WithDescription("Lists all key identities linked to the authenticated user's account."),
				router.WithSuccessResponse(http.StatusOK, "Key identities",
					router.WithJSONContent(dto.KeyIdentityListResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Not authenticated"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Internal server error"),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	}
}

// keyIdentityConnectChallenge issues a challenge for linking a new key to the
// authenticated user's account. The flow is identical to the login challenge,
// but we first check that the key is not already linked to any account.
func (a *API) keyIdentityConnectChallenge(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.KeyIdentityChallengeRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.KeyIdentityChallengeRequest, *dto.KeyIdentityChallengeRequest](ctx, &requestDto)
	if !ok {
		return nil
	}

	handler, ok := core.GetKeyIdentityHandler(requestDto.KeyType)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("unsupported key type: %s", requestDto.KeyType)), http.StatusBadRequest)
	}

	normalizedKey, err := handler.NormalizeKey(requestDto.Key)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	metadata := json.RawMessage(requestDto.Metadata)
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	validatedMetadata, err := handler.ValidateMetadata(metadata)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	// Check if the key is already linked to any account
	exists, _, err := a.user.KeyIdentityExists(c.Request().Context(), requestDto.KeyType, normalizedKey)
	if err != nil {
		a.Logger().Error("failed to check key identity existence", zap.Error(err), zap.String("key_type", requestDto.KeyType))
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusInternalServerError)
	}
	if exists {
		return ctx.Error(core.NewAccountError(core.ErrKeyKeyIdentityExists, fmt.Errorf("key already linked to an account")), http.StatusConflict)
	}

	coreCtx := a.Context().WithRequestContext(c.Request().Context())
	challengeBytes, err := handler.IssueChallenge(coreCtx, normalizedKey, validatedMetadata)
	if err != nil {
		a.Logger().Error("failed to issue connect challenge",
			zap.Error(err),
			zap.String("key_type", requestDto.KeyType),
		)
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	var challenge struct {
		Message string `json:"message"`
		Nonce   string `json:"nonce"`
	}
	if err := json.Unmarshal(challengeBytes, &challenge); err != nil {
		challenge.Message = string(challengeBytes)
	}

	responseModel := &dto.KeyIdentityChallengeResponse{
		Message: challenge.Message,
		Nonce:   challenge.Nonce,
	}
	var responseDto dto.KeyIdentityChallengeResponse
	return httputil.EncodeResponse(ctx, responseModel, &responseDto)
}

// keyIdentityConnectVerify verifies a signed challenge and links the key
// identity to the authenticated user's account.
func (a *API) keyIdentityConnectVerify(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.KeyIdentityConnectVerifyRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.KeyIdentityConnectVerifyRequest, *dto.KeyIdentityConnectVerifyRequest](ctx, &requestDto)
	if !ok {
		return nil
	}

	// Get authenticated user ID
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("not authenticated")), http.StatusUnauthorized)
	}

	handler, ok := core.GetKeyIdentityHandler(requestDto.KeyType)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("unsupported key type: %s", requestDto.KeyType)), http.StatusBadRequest)
	}

	normalizedKey, err := handler.NormalizeKey(requestDto.Key)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	// Re-check that the key is not already linked (race condition between challenge and verify)
	exists, _, err := a.user.KeyIdentityExists(c.Request().Context(), requestDto.KeyType, normalizedKey)
	if err != nil {
		a.Logger().Error("failed to check key identity existence", zap.Error(err))
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusInternalServerError)
	}
	if exists {
		return ctx.Error(core.NewAccountError(core.ErrKeyKeyIdentityExists, fmt.Errorf("key already linked to an account")), http.StatusConflict)
	}

	// Verify proof of ownership
	proof, err := json.Marshal(struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}{
		Message:   requestDto.Message,
		Signature: requestDto.Signature,
	})
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusInternalServerError)
	}

	metadata := json.RawMessage(requestDto.Metadata)
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	validatedMetadata, err := handler.ValidateMetadata(metadata)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	coreCtx := a.Context().WithRequestContext(c.Request().Context())
	if err := handler.VerifyProof(coreCtx, normalizedKey, validatedMetadata, proof); err != nil {
		a.Logger().Error("connect proof verification failed", zap.Error(err), zap.String("key_type", requestDto.KeyType))
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	// Link the key identity to the authenticated user
	if err := a.user.AddKeyIdentity(c.Request().Context(), userID, requestDto.KeyType, normalizedKey, validatedMetadata); err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			if acctErr.Key == core.ErrKeyKeyIdentityExists {
				return ctx.Error(acctErr, http.StatusConflict)
			}
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(core.NewAccountError(core.ErrKeyAddKeyIdentityFailed, err), http.StatusInternalServerError)
	}

	responseModel := &dto.KeyIdentityConnectVerifyResponse{
		KeyType:  requestDto.KeyType,
		Key:      normalizedKey,
		Metadata: dto.NewJSONRawMessageSchema(validatedMetadata),
	}
	var responseDto dto.KeyIdentityConnectVerifyResponse
	return httputil.EncodeResponse(ctx, responseModel, &responseDto)
}

// keyIdentityDisconnect unlinks a key identity from the authenticated user's account.
func (a *API) keyIdentityDisconnect(c echo.Context) error {
	ctx := httputil.Context(c)

	keyType := c.Param("type")
	key := c.Param("key")
	if keyType == "" || key == "" {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("key type and key are required")), http.StatusBadRequest)
	}

	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("not authenticated")), http.StatusUnauthorized)
	}

	handler, ok := core.GetKeyIdentityHandler(keyType)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("unsupported key type: %s", keyType)), http.StatusBadRequest)
	}

	normalizedKey, err := handler.NormalizeKey(key)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	if err := a.user.RemoveKeyIdentity(c.Request().Context(), userID, keyType, normalizedKey); err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			if acctErr.Key == core.ErrKeyKeyIdentityNotFound {
				return ctx.Error(acctErr, http.StatusNotFound)
			}
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err), http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusNoContent)
}

// keyIdentityList returns all key identities linked to the authenticated user.
func (a *API) keyIdentityList(c echo.Context) error {
	ctx := httputil.Context(c)

	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, fmt.Errorf("not authenticated")), http.StatusUnauthorized)
	}

	return queryutilHttp.ProcessListRequest(
		c.Response(),
		c.Request(),
		"key_identities",
		func(filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*models.KeyIdentity, int64, error) {
			return a.user.ListKeyIdentities(c.Request().Context(), userID, filters, sorts, pagination)
		},
		func(id *models.KeyIdentity) *dto.KeyIdentityItem {
			return &dto.KeyIdentityItem{
				KeyType:  id.Type,
				Key:      id.Key,
				Metadata: dto.NewJSONRawMessageSchema(id.Metadata),
			}
		},
	)
}
