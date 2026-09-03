package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

func (a *API) buildKeyIdentityRoutes() []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodPost, "/api/auth/key/challenge", a.keyIdentityChallenge,
			router.WithSwaggerOptions(
				router.WithSummary("Issue Key Identity Challenge"),
				router.WithDescription("Issues a cryptographic challenge for proving ownership of a key identity (e.g., SIWE message for Ethereum)."),
				router.WithRequestBody(dto.KeyIdentityChallengeRequest{}, "Challenge request", true),
				router.WithSuccessResponse(http.StatusOK, "Challenge issued",
					router.WithJSONContent(dto.KeyIdentityChallengeResponse{}),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid key type or key format"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Internal server error"),
				)),
			),
			router.WithAccess(""),
		),
		router.NewRoute(http.MethodPost, "/api/auth/key/verify", a.keyIdentityVerify,
			router.WithSwaggerOptions(
				router.WithSummary("Verify Key Identity and Login"),
				router.WithDescription("Verifies a signed challenge and authenticates the user via key identity login."),
				router.WithRequestBody(dto.KeyIdentityVerifyRequest{}, "Verification request", true),
				router.WithQueryParam("return", "URL to redirect to after completion", "/onboarding"),
				router.WithSuccessResponse(http.StatusOK, "Login successful",
					router.WithJSONContent(dto.KeyIdentityVerifyResponse{}),
				),
				router.WithSuccessResponse(http.StatusFound, "Redirect to auth complete (for non-OTP)",
					router.WithHeader("Location", "URL to redirect to"),
				),
				router.WithErrorResponses(router.DefineSwaggerErrorResponses(
					router.DefineSwaggerErrorResponse(http.StatusBadRequest, "Invalid request or verification failed"),
					router.DefineSwaggerErrorResponse(http.StatusUnauthorized, "Invalid key or proof"),
					router.DefineSwaggerErrorResponse(http.StatusInternalServerError, "Internal server error"),
				)),
			),
			router.WithAccess(""),
		),
	}
}

// keyIdentityChallenge issues a challenge for the given key type and key.
// The handler is looked up from the core registry by key_type.
func (a *API) keyIdentityChallenge(c echo.Context) error {
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

	metadata := json.RawMessage(requestDto.Metadata)
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	validatedMetadata, err := handler.ValidateMetadata(metadata)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	coreCtx := a.Context().WithRequestContext(c.Request().Context())
	challengeBytes, err := handler.IssueChallenge(coreCtx, requestDto.Key, validatedMetadata)
	if err != nil {
		a.Logger().Error("failed to issue key identity challenge",
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

// keyIdentityVerify verifies a signed challenge and logs in the user.
// The proof is constructed from the message + signature in the request,
// marshaled to the JSON format expected by the handler's VerifyProof.
func (a *API) keyIdentityVerify(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.KeyIdentityVerifyRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.KeyIdentityVerifyRequest, *dto.KeyIdentityVerifyRequest](ctx, &requestDto)
	if !ok {
		return nil
	}

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

	coreCtx := a.Context().WithRequestContext(c.Request().Context())
	_jwt, user, err := a.auth.LoginKeyIdentityWithContext(
		coreCtx, requestDto.KeyType, requestDto.Key, proof, ctx.RealIP(), requestDto.Remember,
	)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			a.Logger().Error("key identity login failed", zap.Error(acctErr), zap.String("key_type", requestDto.KeyType))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, err)
		a.Logger().Error("key identity login failed", zap.Error(acctErr), zap.String("key_type", requestDto.KeyType))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if user != nil && user.OTPEnabled {
		// The OTP branch defers the redirect to /api/auth/otp/validate, which
		// must be called with the same `return` parameter to keep the flow
		// intact. Return validation is deferred with it so OTP users always
		// receive the challenge even for an unusable return value.

		// Set short-lived 2FA cookie; do not apply remember-me here
		if err = a.setAuthCookieWithRemember(c, _jwt, false); err != nil {
			acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, err)
			a.Logger().Error("failed to set auth cookie", zap.Error(acctErr))
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}

		// Store remember flag in cookie for later use in OTP validation
		a.storeRememberFlagInCookie(c, requestDto.Remember)

		responseModel := &dto.KeyIdentityVerifyResponse{
			Token: _jwt,
			Otp:   true,
		}
		var responseDto dto.KeyIdentityVerifyResponse
		return httputil.EncodeResponse(ctx, responseModel, &responseDto)
	}

	returnUrl, returnErr := a.requestReturnURL(c, "")
	if returnErr != nil {
		return returnErr
	}

	redirectURL := a.buildAuthCompleteURL(_jwt, returnUrl)
	a.storeRememberFlagInCookie(c, requestDto.Remember)
	return c.Redirect(http.StatusFound, redirectURL)
}
