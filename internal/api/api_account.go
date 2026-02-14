package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	swagger "go.lumeweb.com/gswagger"
	"go.lumeweb.com/httputil"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
	"go.uber.org/zap"
)

func (a *API) buildAccountRoutes(authMw echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodGet, "/api/account", a.accountInfo,
			router.WithSwaggerOptions(
				router.WithSummary("Get account information"),
				router.WithDescription("Retrieves information about the authenticated user's account."),
				router.WithSuccessResponse(http.StatusOK, "Account information",
					router.WithJSONContent(dto.AccountInfoResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Not authenticated"),
					router.DefineSwaggerErrorResponse(http.StatusNotFound, "Account not found"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Failed to retrieve account info"),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodGet, "/api/account/permissions", a.accountPermissions,
			router.WithSwaggerOptions(
				router.WithSummary("Get account permissions"),
				router.WithDescription("Retrieves the access control policies and model for the authenticated user."),
				router.WithResponseHeaders(http.StatusOK, "Account permissions", map[string]swagger.Schema{"application/json": {Value: dto.AccountPermissionsResponse{}}}, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/account/verify-email", a.verifyEmail,
			router.WithSwaggerOptions(
				router.WithSummary("Verify email address"),
				router.WithDescription("Verifies a user's email address using a token sent via email. Optionally auto-login user if they don't have 2FA enabled."),
				router.WithRequestBody(dto.VerifyEmailRequest{}, "Email and verification token", true),
				router.WithQueryParam("login", "Auto-login user after verification (boolean: true/false; also accepts 1/0).", "true"),
				router.WithResponseHeaders(http.StatusOK, "Email verified successfully", nil, nil),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/account/verify-email/resend", a.resendVerifyEmail,
			router.WithSwaggerOptions(
				router.WithSummary("Resend email verification"),
				router.WithDescription("Resends the email verification link to the user's email address."),
				router.WithRequestBody(dto.ResendVerifyEmailRequest{}, "Email address", true),
				router.WithResponseHeaders(http.StatusOK, "Verification email sent (if account exists and is not verified)", nil, nil),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/account/update-email", a.updateEmail,
			router.WithSwaggerOptions(
				router.WithSummary("Update email address"),
				router.WithDescription("Updates the authenticated user's email address."),
				router.WithRequestBody(dto.UpdateEmailRequest{}, "New email and current password", true),
				router.WithResponseHeaders(http.StatusOK, "Email updated successfully", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPatch, "/api/account", a.updateProfile,
			router.WithSwaggerOptions(
				router.WithSummary("Update profile information"),
				router.WithDescription("Updates the authenticated user's profile information. Email cannot be updated through this endpoint."),
				router.WithRequestBody(dto.UpdateProfileRequest{}, "Profile update data", true),
				router.WithResponseHeaders(http.StatusOK, "Profile updated successfully", nil, nil),
				router.WithErrorResponses(accountErrorResponses(
					core.NewAccountError(core.ErrKeyInvalidLogin, nil),
					core.NewAccountError(core.ErrKeyUserNotFound, nil),
					core.NewAccountError(core.ErrKeyDatabaseOperationFailed, nil),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/account/update-password", a.updatePassword,
			router.WithSwaggerOptions(
				router.WithSummary("Update password"),
				router.WithDescription("Updates the authenticated user's password."),
				router.WithRequestBody(dto.UpdatePasswordRequest{}, "Current and new passwords", true),
				router.WithResponseHeaders(http.StatusOK, "Password updated successfully", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodDelete, "/api/account", a.deleteAccount,
			router.WithSwaggerOptions(
				router.WithSummary("Request account deletion"),
				router.WithDescription("Initiates the process to delete the authenticated user's account."),
				router.WithResponseHeaders(http.StatusOK, "Account deletion requested", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/account/password-reset/request", a.passwordResetRequest,
			router.WithSwaggerOptions(
				router.WithSummary("Request password reset"),
				router.WithDescription("Initiates the password reset process by sending a reset link to the user's email."),
				router.WithRequestBody(dto.PasswordResetRequest{}, "Email address", true),
				router.WithSuccessResponse(http.StatusOK, "Password reset email sent (if account exists)"),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, core.NewAccountError(core.ErrKeyInvalidLogin, nil).Message),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, core.NewAccountError(core.ErrKeyDatabaseOperationFailed, nil).Message),
				)),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/account/password-reset/confirm", a.passwordResetConfirm,
			router.WithSwaggerOptions(
				router.WithSummary("Confirm password reset"),
				router.WithDescription("Resets the user's password using a token received via email."),
				router.WithRequestBody(dto.PasswordResetVerifyRequest{}, "Email, token, and new password", true),
				router.WithResponseHeaders(http.StatusOK, "Password reset successfully", nil, nil),
			),
			router.WithAccess(""),
		),
	}
}

func (a *API) accountInfo(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	exists, acct, err := a.user.AccountExists(ctx.Request().Context(), user)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		acctErr := core.NewAccountError(core.ErrKeyUserNotFound, nil)
		return ctx.Error(acctErr, http.StatusNotFound)
	}

	var responseDto dto.AccountInfoResponse
	err = responseDto.FromModel(acct)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if err := a.setAvatarURL(ctx, user, &responseDto); err != nil {
		a.Logger().Error("failed to set avatar URL", zap.Error(err))
	}

	return httputil.EncodeResponse[*models.User](ctx, acct, &responseDto)
}

func (a *API) accountPermissions(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	perms, err := a.access.ExportUserPolicy(ctx.Request().Context(), user)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	model := a.access.ExportModel(ctx.Request().Context())

	responseModel := dto.PermissionsModel{
		Permissions: perms,
		Model:       model,
	}
	var responseDto dto.AccountPermissionsResponse
	return httputil.EncodeResponse[dto.PermissionsModel](ctx, responseModel, &responseDto)
}

func (a *API) verifyEmail(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.VerifyEmailRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.VerifyEmailRequest, *dto.VerifyEmailRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	// First check if account is already verified
	exists, user, err := a.user.EmailExists(ctx.Request().Context(), requestDto.Email)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}
	if !exists {
		return c.NoContent(http.StatusOK)
	}

	verified, err := a.user.IsAccountVerified(ctx.Request().Context(), user.ID)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}
	if verified {
		acctErr := core.NewAccountError(core.ErrKeyAccountAlreadyVerified, nil)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	// Only attempt verification if not already verified
	err = a.user.VerifyEmail(ctx.Request().Context(), requestDto.Email, requestDto.Token)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	// Check for auto-login query parameter
	autoLogin := false
	remember := false
	if loginParam := c.QueryParam("login"); loginParam != "" {
		autoLogin, _ = strconv.ParseBool(loginParam)
		remember, _ = strconv.ParseBool(loginParam)
	}

	// If auto-login is requested and user doesn't have 2FA enabled
	if autoLogin && !user.OTPEnabled {
		// Check if user is already logged in
		_, authErr := mcontext.GetAuthToken(ctx.Context)
		if authErr != nil {
			// User is not logged in, so we can proceed with auto-login
			_jwt, loginErr := a.auth.LoginID(ctx.Request().Context(), user.ID, ctx.RealIP(), remember)
			if loginErr != nil {
				acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, loginErr)
				a.Logger().Error("failed to auto-login after email verification", zap.Error(acctErr))
				// Don't return error here - email verification was successful, just auto-login failed
			} else {
				// Set the authentication cookie with the remember flag
				if setCookieErr := a.setAuthCookieWithRemember(c, _jwt, remember); setCookieErr != nil {
					acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, setCookieErr)
					a.Logger().Error("failed to set auth cookie after email verification", zap.Error(acctErr))
					// Don't return error here - email verification was successful, just cookie setting failed
				}
			}
		}
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) resendVerifyEmail(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.ResendVerifyEmailRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.ResendVerifyEmailRequest, *dto.ResendVerifyEmailRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	exists, _user, err := a.user.EmailExists(ctx.Request().Context(), requestDto.Email)

	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		return c.NoContent(http.StatusOK)
	}

	err = a.user.SendEmailVerification(ctx.Request().Context(), _user.ID)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			if acctErr.IsErrorType(core.ErrKeyAccountAlreadyVerified) {
				return c.NoContent(http.StatusOK)
			}
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) updateEmail(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var requestDto dto.UpdateEmailRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.UpdateEmailRequest, *dto.UpdateEmailRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	err := a.user.UpdateAccountEmail(ctx.Request().Context(), user, requestDto.Email, requestDto.Password)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) updatePassword(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var requestDto dto.UpdatePasswordRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.UpdatePasswordRequest, *dto.UpdatePasswordRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	err := a.user.UpdateAccountPassword(ctx.Request().Context(), user, requestDto.CurrentPassword, requestDto.NewPassword)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

// getInputValue safely gets a string value from input pointer, falling back to default if nil or empty
func getInputValue(input *string, defaultValue string) string {
	if input == nil {
		return defaultValue
	}
	trimmed := strings.TrimSpace(*input)
	if trimmed != "" {
		return trimmed
	}
	return defaultValue
}

func (a *API) updateProfile(c echo.Context) error {
	ctx := httputil.Context(c)
	userID, ok := a.getUser(ctx)
	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var requestDto dto.UpdateProfileRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.UpdateProfileRequest, *dto.UpdateProfileRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	// Get existing user values if fields are empty
	exists, existingUser, err := a.user.AccountExists(ctx.Request().Context(), userID)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			a.Logger().Error("failed to find user", zap.Error(acctErr), zap.Uint("user_id", userID))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		a.Logger().Error("failed to find user", zap.Error(acctErr), zap.Uint("user_id", userID))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		acctErr := core.NewAccountError(core.ErrKeyUserNotFound, nil)
		a.Logger().Error("user not found", zap.Error(acctErr))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	firstName := getInputValue(requestDto.FirstName, existingUser.FirstName)
	lastName := getInputValue(requestDto.LastName, existingUser.LastName)

	// Short-circuit if there are no changes
	if firstName == existingUser.FirstName && lastName == existingUser.LastName {
		a.Logger().Debug("no profile changes; skipping update", zap.Uint("user_id", userID))
		return c.NoContent(http.StatusOK)
	}

	err = a.user.UpdateAccountName(ctx.Request().Context(), userID, firstName, lastName)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			a.Logger().Error("failed to update profile", zap.Error(acctErr), zap.Uint("user_id", userID))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		a.Logger().Error("failed to update profile", zap.Error(acctErr), zap.Uint("user_id", userID))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) deleteAccount(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	err := a.user.RequestAccountDeletion(ctx.Request().Context(), user, ctx.RealIP())
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			if acctErr.IsErrorType(core.ErrKeyAccountDeletionRequestAlreadyExists) {
				return ctx.Error(acctErr, acctErr.HttpStatus())
			}
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	a.cookieSetter().ClearJWTCookie(c.Response())

	// Clear the remember-me cookie to prevent preference bleed
	a.clearRememberMeCookie(c)

	return c.NoContent(http.StatusOK)
}

func (a *API) passwordResetRequest(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.PasswordResetRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.PasswordResetRequest, *dto.PasswordResetRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	exists, user, err := a.user.EmailExists(ctx.Request().Context(), requestDto.Email)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		return c.NoContent(http.StatusOK)
	}

	err = a.password.SendPasswordReset(ctx.Request().Context(), user)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) passwordResetConfirm(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.PasswordResetVerifyRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.PasswordResetVerifyRequest, *dto.PasswordResetVerifyRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	exists, _, err := a.user.EmailExists(ctx.Request().Context(), requestDto.Email)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		return ctx.Error(errors.New("invalid request"), http.StatusBadRequest)
	}

	err = a.password.ResetPassword(ctx.Request().Context(), requestDto.Email, requestDto.Token, requestDto.Password)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}
