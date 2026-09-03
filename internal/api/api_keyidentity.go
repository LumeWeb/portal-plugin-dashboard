package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
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
				router.WithDescription("Verifies a signed challenge and authenticates the user via key identity login. If the key is not linked to any account, a new anonymous account is provisioned (response/redirect carries new_account)."),
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
//
// If the key is not linked to any account yet, a new anonymous account is
// provisioned (generated email via core.AnonEmail, unguessable password,
// key identity linked) using the submitted metadata, mirroring the social
// login UPSERT. The response flags this via new_account (or new_account=1
// on the auth-complete redirect) so clients can route to onboarding.
func (a *API) keyIdentityVerify(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.KeyIdentityVerifyRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.KeyIdentityVerifyRequest, *dto.KeyIdentityVerifyRequest](ctx, &requestDto)
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

	exists, _, err := a.user.KeyIdentityExists(c.Request().Context(), requestDto.KeyType, normalizedKey)
	if err != nil {
		return a.encodeKeyIdentityError(ctx, asLoginError(err), requestDto.KeyType, "failed to check key identity existence")
	}

	var (
		_jwt       string
		user       *models.User
		newAccount bool
	)

	if exists {
		_jwt, user, err = a.auth.LoginKeyIdentityWithContext(
			coreCtx, requestDto.KeyType, normalizedKey, proof, ctx.RealIP(), requestDto.Remember,
		)
		if err != nil {
			return a.encodeKeyIdentityError(ctx, asLoginError(err), requestDto.KeyType, "key identity login failed")
		}
	} else {
		var created bool
		_jwt, user, created, err = a.registerAnonKeyIdentity(c, coreCtx, requestDto, handler, normalizedKey, proof)
		if err != nil {
			return err // response already encoded by the registration helper
		}
		newAccount = created
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
			Token:      _jwt,
			Otp:        true,
			NewAccount: newAccount,
		}
		var responseDto dto.KeyIdentityVerifyResponse
		return httputil.EncodeResponse(ctx, responseModel, &responseDto)
	}

	returnUrl, returnErr := a.requestReturnURL(c, "")
	if returnErr != nil {
		return returnErr
	}

	redirectURL := a.buildAuthCompleteURL(_jwt, returnUrl)
	if newAccount {
		if u, perr := url.Parse(redirectURL); perr == nil {
			q := u.Query()
			q.Set("new_account", "1")
			u.RawQuery = q.Encode()
			redirectURL = u.String()
		}
	}
	a.storeRememberFlagInCookie(c, requestDto.Remember)
	return c.Redirect(http.StatusFound, redirectURL)
}

// asLoginError normalizes any login failure into an account error suitable
// for HTTP encoding.
func asLoginError(err error) *core.Error {
	if acctErr := core.AsAccountError(err); acctErr != nil {
		return acctErr
	}
	return core.NewAccountError(core.ErrKeyInvalidLogin, err)
}

// encodeKeyIdentityError logs an account error with the key type and returns
// it as an already-encoded HTTP response for ctx.Error to write.
func (a *API) encodeKeyIdentityError(ctx httputil.RequestContext, acctErr *core.Error, keyType, msg string) error {
	a.Logger().Error(msg, zap.Error(acctErr), zap.String("key_type", keyType))
	return ctx.Error(acctErr, acctErr.HttpStatus())
}

// registerAnonKeyIdentity provisions a new anonymous account for a key that
// is not linked to any account yet. The proof is verified against the
// metadata submitted with the verify request (the challenge was issued for
// it), then the account is created with a generated email and an unguessable
// password, the key identity is linked, and a login token is issued.
// The created flag is false when a concurrent request already provisioned
// the account and this request fell back to logging in instead.
// It returns encoded error responses via ctx and a nil error only when
// a login token was produced.
func (a *API) registerAnonKeyIdentity(
	c echo.Context,
	coreCtx core.Context,
	requestDto dto.KeyIdentityVerifyRequest,
	handler core.KeyIdentityHandler,
	normalizedKey string,
	proof []byte,
) (string, *models.User, bool, error) {
	ctx := httputil.Context(c)

	metadata := json.RawMessage(requestDto.Metadata)
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	validatedMetadata, err := handler.ValidateMetadata(metadata)
	if err != nil {
		return "", nil, false, ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, err), http.StatusBadRequest)
	}

	if err := handler.VerifyProof(coreCtx, normalizedKey, validatedMetadata, proof); err != nil {
		return "", nil, false, a.encodeKeyIdentityError(ctx, asLoginError(err), requestDto.KeyType,
			"anon key identity registration proof verification failed")
	}

	password, err := generateRandomString(32)
	if err != nil {
		return "", nil, false, a.encodeKeyIdentityError(ctx,
			core.NewAccountError(core.ErrKeySocialAccountCreationFailed, err), requestDto.KeyType,
			"anon key identity account creation failed")
	}

	user, err := a.user.CreateAccount(c.Request().Context(), core.AnonEmail(normalizedKey), password, false, core.WithBootstrapAdmin(false))
	if err != nil {
		token, winner, err := a.recoverCreateAccountFailure(ctx, err, requestDto, normalizedKey, coreCtx, proof)
		if err != nil {
			return "", nil, false, err
		}
		return token, winner, false, nil
	}

	// rollBack removes the just-created account. Its password is unguessable
	// and its email is not routable, so anything failing from here on leaves
	// an account that no one can ever log into or claim — delete it.
	rollBack := func(acctErr *core.Error, msg string) (string, *models.User, bool, error) {
		if derr := a.user.DeleteAccount(c.Request().Context(), user.ID); derr != nil {
			a.Logger().Error("failed to delete orphan anon account", zap.Error(derr), zap.Uint("user_id", user.ID))
		}
		return "", nil, false, a.encodeKeyIdentityError(ctx, acctErr, requestDto.KeyType, msg)
	}

	// There is no mailbox to confirm; the account is usable immediately.
	if err := a.user.UpdateAccountInfo(c.Request().Context(), user.ID, map[string]any{"verified": true}); err != nil {
		return rollBack(core.NewAccountError(core.ErrKeySocialAccountCreationFailed, err),
			"failed to mark anon account verified")
	}
	user.Verified = true

	if err := a.user.AddKeyIdentity(c.Request().Context(), user.ID, requestDto.KeyType, normalizedKey, validatedMetadata); err != nil {
		return rollBack(wrapSocialError(err), "failed to link key identity to new anon account")
	}

	token, err := a.auth.LoginID(c.Request().Context(), user.ID, ctx.RealIP(), requestDto.Remember)
	if err != nil {
		return rollBack(core.NewAccountError(core.ErrKeyInvalidLogin, err), "failed to issue login token for anon account")
	}

	return token, user, true, nil
}

// wrapSocialError preserves typed account errors and wraps anything else as a
// social account creation failure.
func wrapSocialError(err error) *core.Error {
	if acctErr := core.AsAccountError(err); acctErr != nil {
		return acctErr
	}
	return core.NewAccountError(core.ErrKeySocialAccountCreationFailed, err)
}

// recoverCreateAccountFailure handles a CreateAccount failure during anon
// wallet registration. The anon email is derived from the key, so a collision
// means a concurrent verify just provisioned the account; if the key is now
// linked, this request falls back to logging in as the winner instead of
// failing the loser of the race. A non-nil fatalErr is an already-encoded
// HTTP response; token and user are only set on the fallback-login path.
func (a *API) recoverCreateAccountFailure(
	ctx httputil.RequestContext,
	err error,
	requestDto dto.KeyIdentityVerifyRequest,
	normalizedKey string,
	coreCtx core.Context,
	proof []byte,
) (string, *models.User, error) {
	keyType := requestDto.KeyType
	if !core.IsAccountError(err) {
		return "", nil, a.encodeKeyIdentityError(ctx,
			core.NewAccountError(core.ErrKeySocialAccountCreationFailed, err), keyType,
			"anon key identity account creation failed")
	}
	acctErr := core.AsAccountError(err)
	if acctErr.Key != core.ErrKeyEmailAlreadyExists {
		return "", nil, a.encodeKeyIdentityError(ctx, acctErr, keyType, "anon key identity account creation failed")
	}

	linked, _, lerr := a.user.KeyIdentityExists(ctx.Request().Context(), keyType, normalizedKey)
	if lerr != nil || !linked {
		return "", nil, a.encodeKeyIdentityError(ctx, acctErr, keyType, "anon key identity account creation failed")
	}

	// The winner linked the key: log in through the normal path.
	token, user, err := a.auth.LoginKeyIdentityWithContext(
		coreCtx, keyType, normalizedKey, proof, ctx.RealIP(), requestDto.Remember,
	)
	if err != nil {
		return "", nil, a.encodeKeyIdentityError(ctx, asLoginError(err), keyType, "key identity login failed")
	}
	return token, user, nil
}
