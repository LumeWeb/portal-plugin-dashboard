package api

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
)

func (a *API) buildOTPRoutes(authMw echo.MiddlewareFunc, loginAuthMw2fa echo.MiddlewareFunc, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodPost, "/api/auth/otp/generate", a.otpGenerate,
			router.WithSwaggerOptions(
				router.WithSummary("Generate OTP secret"),
				router.WithDescription("Generates a new OTP secret for the authenticated user."),
				router.WithSuccessResponse(http.StatusOK, "OTP secret generated",
					router.WithJSONContent(dto.OTPGenerateResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, core.NewAccountError(core.ErrKeyInvalidLogin, nil).Message),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, core.NewAccountError(core.ErrKeyOTPGenerationFailed, nil).Message),
				)),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/auth/otp/validate", a.otpValidate,
			router.WithSwaggerOptions(
				router.WithSummary("Validate OTP code"),
				router.WithDescription("Validates an OTP code to complete 2FA login."),
				router.WithRequestBody(dto.OTPValidateRequest{}, "OTP code", true),
				router.WithSuccessResponse(http.StatusFound, "Redirect to auth complete (on success)",
					router.WithHeader("Location", "URL to redirect to"),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid OTP code"),
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Invalid login session"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Failed to validate OTP"),
				)),
			),
			router.WithAccess(""),
			router.WithMiddlewares(loginAuthMw2fa),
		),
		router.NewRoute(http.MethodPost, "/api/auth/otp/verify", a.otpVerify,
			router.WithSwaggerOptions(
				router.WithSummary("Verify and enable OTP"),
				router.WithDescription("Verifies an OTP code and enables 2FA for the authenticated user."),
				router.WithRequestBody(dto.OTPVerifyRequest{}, "OTP code", true),
				router.WithResponseHeaders(http.StatusNoContent, "OTP verified and enabled", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/auth/otp/disable", a.otpDisable,
			router.WithSwaggerOptions(
				router.WithSummary("Disable OTP"),
				router.WithDescription("Disables 2FA for the authenticated user."),
				router.WithRequestBody(dto.OTPDisableRequest{}, "Current password", true),
				router.WithResponseHeaders(http.StatusNoContent, "OTP disabled", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	}
}

func (a *API) otpGenerate(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	otp, err := a.otp.OTPGenerate(ctx.Request().Context(), user)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyOTPGenerationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	responseModel := &dto.OTPGenerateResponse{
		OTP: otp,
	}
	var responseDto dto.OTPGenerateResponse
	return httputil.EncodeResponse(ctx, responseModel, &responseDto)
}

func (a *API) otpVerify(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var requestDto dto.OTPVerifyRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.OTPVerifyRequest, *dto.OTPVerifyRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	err := a.otp.OTPEnable(ctx.Request().Context(), user, requestDto.OTP)
	if err != nil {
		if errors.Is(err, core.ErrInvalidOTPCode) {
			acctErr := core.NewAccountError(core.ErrKeyInvalidOTPCode, nil)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}

		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusNoContent)
}

func (a *API) otpValidate(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var request dto.OTPValidateRequest

	_, ok = httputil.DecodeAndValidateRequest[*dto.OTPValidateRequest, *dto.OTPValidateRequest](ctx, &request)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	// Retrieve the remember flag from cookies
	remember := a.getRememberFlagFromCookie(ctx)
	_jwt, err := a.auth.LoginOTP(ctx.Request().Context(), user, request.OTP, remember)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	redirectURL := a.buildAuthCompleteURL(_jwt, "")

	// Set the authentication cookie with the remember flag
	if err := a.setAuthCookieWithRemember(c, _jwt, remember); err != nil {
		loginFailed(ctx, err)
		return nil
	}

	return c.Redirect(http.StatusFound, redirectURL)
}

func (a *API) otpDisable(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var request dto.OTPDisableRequest
	_, ok = httputil.DecodeAndValidateRequest[*dto.OTPDisableRequest, *dto.OTPDisableRequest](ctx, &request)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	valid, _, err := a.auth.ValidLoginByUserID(ctx.Request().Context(), user, request.Password)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.JSON(acctErr.HttpStatus(), acctErr)
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.JSON(acctErr.HttpStatus(), acctErr)
	}

	if !valid {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		return ctx.Error(err, http.StatusUnauthorized)
	}

	err = a.otp.OTPDisable(ctx.Request().Context(), user)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusNoContent)
}
