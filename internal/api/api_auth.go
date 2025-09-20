package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

func (a *API) buildAuthRoutes(authMw echo.MiddlewareFunc, loginAuthMw2fa echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodPost, "/api/auth/register", a.register,
			router.WithSwaggerOptions(
				router.WithSummary("Register a new account"),
				router.WithDescription("Creates a new user account with email and password."),
				router.WithRequestBody(dto.RegisterRequest{}, "Registration details", true),
				router.WithSuccessResponse(http.StatusOK, "Account created successfully"),
				router.WithErrorResponses(accountErrorResponses(
					core.NewAccountError(core.ErrKeyAccountCreationFailed, nil),
					core.NewAccountError(core.ErrKeyEmailAlreadyExists, nil),
					core.NewAccountError(core.ErrKeyDatabaseOperationFailed, nil),
				)),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/auth/login", a.login,
			router.WithSwaggerOptions(
				router.WithSummary("Login with email and password"),
				router.WithDescription("Authenticates a user using email and password."),
				router.WithRequestBody(dto.LoginRequest{}, "Login credentials", true),
				router.WithSuccessResponse(http.StatusOK, "OTP required",
					router.WithJSONContent(dto.LoginResponse{}),
				),
				router.WithSuccessResponse(http.StatusFound, "Redirect to auth complete (for non-OTP)",
					router.WithHeader("Location", "URL to redirect to"),
				),
				router.WithErrorResponses(accountErrorResponses(
					core.NewAccountError(core.ErrKeyInvalidLogin, nil),
					core.NewAccountError(core.ErrKeyAccountNotVerified, nil),
					core.NewAccountError(core.ErrKeyAccountPendingDeletion, nil),
					core.NewAccountError(core.ErrKeyLoginFailed, nil),
				)),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/auth/logout", a.logout,
			router.WithSwaggerOptions(
				router.WithSummary("Logout"),
				router.WithDescription("Logs out the current user by clearing the authentication cookie."),
				router.WithSuccessResponse(http.StatusOK, "Logout successful"),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Failed to logout"),
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Not authenticated"),
				)),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/auth/ping", a.ping,
			router.WithSwaggerOptions(
				router.WithSummary("Ping authenticated endpoint"),
				router.WithDescription("Checks if the user is authenticated and returns a pong response."),
				router.WithSuccessResponse(http.StatusOK, "Authenticated",
					router.WithJSONContent(dto.PongResponse{}),
				),
				router.WithErrorResponses(accountErrorResponses(
					core.NewAccountError(core.ErrKeyInvalidLogin, nil),
					core.NewAccountError(core.ErrKeyDatabaseOperationFailed, nil),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/auth/key", a.authWithAPIKey,
			router.WithSwaggerOptions(
				router.WithSummary("Authenticate with API Key"),
				router.WithDescription("Exchanges an API key for a JWT."),
				router.WithHeaderParam("Authorization", "API Key followed by the key", "APIKey <your_key>"),
				router.WithSuccessResponse(http.StatusOK, "JWT issued",
					router.WithJSONContent(dto.LoginResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, core.NewAccountError(core.ErrKeyInvalidLogin, nil).Message),
					router.DefineSwaggerErrorResponse(http.StatusForbidden, core.NewAccountError(core.ErrKeyAccountNotVerified, nil).Message),
					router.DefineSwaggerErrorResponse(http.StatusForbidden, core.NewAccountError(core.ErrKeyAccountPendingDeletion, nil).Message),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, core.NewAccountError(core.ErrKeyDatabaseOperationFailed, nil).Message),
				)),
			),
			router.WithAccess(""),
		),
	}
}

func (a *API) buildRootAuthCompleteRoute() []router.Route {
	authMw := middleware.AuthMiddleware(a.ctx, middleware.WithAuthPurpose(jwt.PurposeLogin))

	return []router.Route{
		router.NewRoute(http.MethodGet, "/api/auth/complete", a.rootAuthComplete,
			router.WithSwaggerOptions(
				router.WithSummary("Authentication Complete Redirect"),
				router.WithDescription("Handles the final redirect after successful authentication (password or social). Sets authentication cookies and redirects to the return URL."),
				router.WithQueryParam("return", "URL to redirect to after completion", ""),
				router.WithResponseHeaders(http.StatusFound, "Redirecting to return URL", nil, nil),
			),
			router.WithMiddlewares(authMw),
		),
	}
}

func (a *API) login(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.LoginRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.LoginRequest, *dto.LoginRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	exists, _, err := a.user.EmailExists(requestDto.Email)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		a.logger.Error("failed to check if email exists", zap.Error(acctErr), zap.String("email", requestDto.Email))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		return ctx.Error(err, http.StatusUnauthorized)
	}

	_jwt, user, err := a.auth.LoginPassword(requestDto.Email, requestDto.Password, ctx.Request().RemoteAddr, requestDto.Remember)
	if err != nil || user == nil {
		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, err)
		a.logger.Error("failed to login", zap.Error(acctErr))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if user.OTPEnabled {
		// Set short-lived 2FA cookie; do not apply remember-me here
		if err = a.setAuthCookieWithRemember(c, _jwt, false); err != nil {
			acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, err)
			a.logger.Error("failed to set auth cookie", zap.Error(acctErr))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}

		// Store remember flag in cookie for later use in OTP validation
		// Always call storeRememberFlagInCookie to ensure proper cookie state
		a.storeRememberFlagInCookie(c, requestDto.Remember)

		responseModel := &dto.LoginResponse{
			Token: _jwt,
			Otp:   true,
		}
		var responseDto dto.LoginResponse
		return httputil.EncodeResponse(ctx, responseModel, &responseDto)
	}

	redirectURL := a.buildAuthCompleteURL(_jwt, "")

	// For non-OTP login, ensure remember cookie is properly set/cleared
	a.storeRememberFlagInCookie(c, requestDto.Remember)

	return c.Redirect(http.StatusFound, redirectURL)
}

func (a *API) register(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.RegisterRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.RegisterRequest, *dto.RegisterRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	user, err := a.user.CreateAccount(requestDto.Email, requestDto.Password, true)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			a.logger.Error("failed to create account", zap.Error(acctErr))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyAccountCreationFailed, err)
		a.logger.Error("failed to create account", zap.Error(acctErr))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	err = a.user.UpdateAccountName(user.ID, requestDto.FirstName, requestDto.LastName)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			a.logger.Error("failed to update account name", zap.Error(acctErr), zap.Uint("user_id", user.ID))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyAccountCreationFailed, err)
		a.logger.Error("failed to update account name", zap.Error(acctErr), zap.Uint("user_id", user.ID))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusOK)
}
