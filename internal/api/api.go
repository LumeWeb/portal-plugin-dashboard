package api

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	jwt2 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4" // Import echo
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/samber/lo"
	"github.com/sethvargo/go-password/password"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-middleware/cors"
	"go.lumeweb.com/portal-middleware/middleware"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	_ "go.lumeweb.com/portal-plugin-dashboard/internal/provider/providers"
	"go.lumeweb.com/portal-plugin-dashboard/internal/service"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	_ "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/portal/event"
	"go.lumeweb.com/queryutil"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	portal_dashboard "go.lumeweb.com/web/go/portal-dashboard"
	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/url"
	"time"

	swagger "go.lumeweb.com/gswagger"
	router "go.lumeweb.com/portal-router"
)

const returnSessionKey = "return"

var _ core.API = (*API)(nil)

type API struct {
	ctx      core.Context
	config   config.Manager
	user     core.UserService
	auth     core.AuthService
	password core.PasswordResetService
	otp      core.OTPService
	apiKey   service.APIKeyService
	access   core.AccessService
	logger   *core.Logger
}

func (a *API) OpenAPIInfo() router.APIInfoDefinition {
	// Implement the OpenAPIInfo method using the router.APIInfo builder
	return router.APIInfo().
		Title("Account API").Description("API endpoints for managing user accounts, authentication, and API keys.")
}

func (a *API) Config() config.APIConfig {
	return &pluginConfig.APIConfig{}
}

func (a *API) Name() string {
	return "account"
}

func NewAPI() (core.API, []core.ContextBuilderOption, error) {
	api := &API{}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			api.ctx = ctx
			api.config = ctx.Config()
			api.user = ctx.Service(core.USER_SERVICE).(core.UserService)
			api.auth = ctx.Service(core.AUTH_SERVICE).(core.AuthService)
			api.password = ctx.Service(core.PASSWORD_RESET_SERVICE).(core.PasswordResetService)
			api.otp = ctx.Service(core.OTP_SERVICE).(core.OTPService)
			api.apiKey = ctx.Service(service.API_KEY_SERVICE).(service.APIKeyService)
			api.access = ctx.Service(core.ACCESS_SERVICE).(core.AccessService)
			api.logger = ctx.APILogger(api)

			return nil
		}),
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			err := event.FireUseServicerSubdomainSetEvent(ctx, api.Subdomain())
			if err != nil {
				return err
			}
			return nil
		}),

		core.ContextWithStartupFunc(func(ctx core.Context) error {
			pluginCfg := ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

			if pluginCfg.SocialLogin.Enabled {
				authCookieKey, err := generateSocialKey(ctx, "auth")
				if err != nil {
					return err
				}

				encCookieKey, err := generateSocialKey(ctx, "encrypt")
				if err != nil {
					return err
				}

				cookieStore := sessions.NewCookieStore(authCookieKey, encCookieKey)
				cookieStore.Options.HttpOnly = true
				gothic.Store = cookieStore

				for _provider, providerConfig := range pluginCfg.SocialLogin.Provider {
					if !providerConfig.Enabled || !provider.ProviderExists(_provider) {
						continue
					}

					provider.ConfigureProvider(_provider, providerConfig)
				}

				if pluginCfg.SocialLogin.Order != nil && len(pluginCfg.SocialLogin.Order) > 0 {
					provider.SetProviderOrder(lo.Filter(pluginCfg.SocialLogin.Order, func(item string, _ int) bool {
						return provider.ProviderExists(item)
					}))
				}

				provider.Provider().SetContext(ctx)

				for _, providerId := range provider.EnabledProviders() {
					_provider, err := provider.CreateProvider(providerId)
					if err != nil {
						return err
					}
					goth.UseProviders(_provider)
				}
			}

			return nil
		}),
	)

	return api, opts, nil
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
		a.logger.Error("failed to check if email exists", zap.Error(acctErr))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		return ctx.Error(err, http.StatusUnauthorized)
	}

	_jwt, user, err := a.auth.LoginPassword(requestDto.Email, requestDto.Password, c.Request().RemoteAddr, requestDto.Remember)
	if err != nil || user == nil {
		acctErr := core.NewAccountError(core.ErrKeyInvalidLogin, err)
		a.logger.Error("failed to login", zap.Error(acctErr))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if user.OTPEnabled {
		responseModel := &dto.LoginResponse{
			Token: _jwt,
			Otp:   true,
		}
		var responseDto dto.LoginResponse
		return httputil.EncodeResponse(ctx, responseModel, &responseDto)
	}

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), _jwt)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

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
		acctErr := core.NewAccountError(core.ErrKeyAccountCreationFailed, err)
		a.logger.Error("failed to update account name", zap.Error(acctErr))
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	err = a.user.UpdateAccountName(user.ID, requestDto.FirstName, requestDto.LastName)
	if err != nil {
		err := core.NewAccountError(core.ErrKeyAccountCreationFailed, err)
		a.logger.Error("failed to update account name", zap.Error(err))
		return ctx.Error(err, http.StatusBadRequest)
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) verifyEmail(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.VerifyEmailRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.VerifyEmailRequest, *dto.VerifyEmailRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	err := a.user.VerifyEmail(requestDto.Email, requestDto.Token)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
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

	exists, _user, err := a.user.EmailExists(requestDto.Email)

	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		return c.NoContent(http.StatusOK)
	}

	err = a.user.SendEmailVerification(_user.ID)
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

func (a *API) otpGenerate(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	otp, err := a.otp.OTPGenerate(user)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
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

	err := a.otp.OTPEnable(user, requestDto.OTP)
	if err != nil {
		if errors.Is(err, core.ErrInvalidOTPCode) {
			acctErr := core.NewAccountError(core.ErrKeyInvalidOTPCode, nil)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}

		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusOK)
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

	_jwt, err := a.auth.LoginOTP(user, request.OTP)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), _jwt)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

	return c.Redirect(http.StatusFound, redirectURL)
}
func (a *API) otpDisable(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	var request dto.OTPDisableRequest
	err := ctx.Decode(&request)
	if err != nil {
		return err
	}

	valid, _, err := a.auth.ValidLoginByUserID(user, request.Password)
	if err != nil {
		err := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.JSON(acctErr.HttpStatus(), acctErr)
	}

	if !valid {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		return ctx.Error(err, http.StatusUnauthorized)
	}

	err = a.otp.OTPDisable(user)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	return c.NoContent(http.StatusOK)
}
func (a *API) passwordResetRequest(c echo.Context) error {
	ctx := httputil.Context(c)

	var requestDto dto.PasswordResetRequest
	_, ok := httputil.DecodeAndValidateRequest[*dto.PasswordResetRequest, *dto.PasswordResetRequest](ctx, &requestDto)
	if !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	exists, user, err := a.user.EmailExists(requestDto.Email)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		return c.NoContent(http.StatusOK)
	}

	err = a.password.SendPasswordReset(user)
	if err != nil {
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

	exists, _, err := a.user.EmailExists(requestDto.Email)
	if err != nil {
		acctErr := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}

	if !exists {
		return ctx.Error(errors.New("invalid request"), http.StatusBadRequest)
	}

	err = a.password.ResetPassword(requestDto.Email, requestDto.Token, requestDto.Password)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.Error(errors.New("API key not found"), http.StatusNotFound)
	} else if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}
func (a *API) ping(c echo.Context) error {
	ctx := httputil.Context(c)

	token, ok := a.getAuthToken(ctx)

	if !ok {
		return nil
	}

	adapter.NewMultiCookieSetter(adapter.NewFromCore(a.ctx), adapter.NewAPIProvider()).EchoAuthCookie(c.Response(), c.Request())
	jwt.SendHeader(c.Response(), token)

	response := &dto.PongResponse{
		Ping:  "pong",
		Token: token,
	}
	return httputil.EncodeResponse(ctx, response, response)
}

func (a *API) rootAuthComplete(c echo.Context) error {
	ctx := httputil.Context(c)
	userId, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}
	token, ok := a.getAuthToken(ctx)
	if !ok {
		return nil
	}

	exists, user, err := a.user.AccountExists(userId)
	if err != nil {
		a.logger.Error("failed to check if email exists", zap.Error(err))
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if !exists {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	returnUrl := c.QueryParam("return")

	decodeToken, err := jwt.DecodeToken(token, &jwt.RegisteredClaims{})
	if err != nil {
		loginFailed(ctx, err)
	}

	sub, err := decodeToken.GetSubject()
	if err != nil {
		loginFailed(ctx, err)
	}

	aud, err := decodeToken.GetAudience()
	if err != nil {
		loginFailed(ctx, err)
	}

	exp, err := decodeToken.GetExpirationTime()
	if err != nil {
		loginFailed(ctx, err)
	}

	_, err = adapter.NewMultiCookieSetter(adapter.NewFromCore(a.ctx), adapter.NewAPIProvider()).SetJWTCookie(c.Response(), sub, jwt.Purpose(aud[0]), exp.Time.Sub(time.Now()))
	if err != nil {
		loginFailed(ctx, err)
	}

	if len(returnUrl) > 0 {
		return c.Redirect(http.StatusFound, returnUrl)
	}

	responseModel := &dto.LoginResponse{
		Token: token,
		Otp:   user.OTPEnabled && user.OTPVerified,
	}
	var responseDto dto.LoginResponse
	return httputil.EncodeResponse(ctx, responseModel, &responseDto)
}

func (a *API) accountInfo(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	_, acct, err := a.user.AccountExists(user)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	var responseDto dto.AccountInfoResponse
	return httputil.EncodeResponse[*models.User](ctx, acct, &responseDto)
}

func (a *API) accountPermissions(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	perms, err := a.access.ExportUserPolicy(user)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	model := a.access.ExportModel()

	responseModel := dto.PermissionsModel{
		Permissions: perms,
		Model:       model,
	}
	var responseDto dto.AccountPermissionsResponse
	return httputil.EncodeResponse[dto.PermissionsModel](ctx, responseModel, &responseDto)
}

func (a *API) logout(c echo.Context) error {
	adapter.NewMultiCookieSetter(adapter.NewFromCore(a.ctx), adapter.NewAPIProvider()).ClearJWTCookie(c.Response())
	return c.NoContent(http.StatusOK)
}

func (a *API) uploadLimit(c echo.Context) error {
	ctx := httputil.Context(c)
	responseModel := &dto.UploadLimitResponse{
		Limit: a.config.Config().Core.PostUploadLimit,
	}
	var responseDto dto.UploadLimitResponse
	return httputil.EncodeResponse[*dto.UploadLimitResponse](ctx, responseModel, &responseDto)
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

	err := a.user.UpdateAccountEmail(user, requestDto.Email, requestDto.Password)
	if err != nil {
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

	err := a.user.UpdateAccountPassword(user, requestDto.CurrentPassword, requestDto.NewPassword)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

func (a *API) getUser(ctx httputil.RequestContext) (uint, bool) {
	user, err := mcontext.GetUserID(ctx.Context)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return 0, false
	}

	return user, true
}

func (a *API) getAuthToken(ctx httputil.RequestContext) (string, bool) {
	token, err := mcontext.GetAuthToken(ctx.Context)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return "", false
	}

	return token, true
}

func (a *API) socialAuthLogin(c echo.Context) error {
	ctx := httputil.Context(c)

	returnUrl := c.QueryParam(returnSessionKey)

	if returnUrl == "" {
		return ctx.Error(errors.New("return missing"), http.StatusBadRequest)
	}

	err := gothic.StoreInSession(returnSessionKey, returnUrl, c.Request(), c.Response())
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request()); err == nil {
		a.setupOrLoginSocialUser(&gothUser, ctx, returnUrl)
		return c.NoContent(http.StatusOK)
	}

	gothic.BeginAuthHandler(c.Response(), c.Request())
	return nil
}

func (a *API) socialAuthCallback(c echo.Context) error {
	ctx := httputil.Context(c)
	returnUrl, err := gothic.GetFromSession(returnSessionKey, c.Request())
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request())

	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	a.setupOrLoginSocialUser(&gothUser, ctx, returnUrl)
	return nil
}

func (a *API) socialAuthLogout(c echo.Context) error {
	ctx := httputil.Context(c)
	err := gothic.Logout(c.Response(), c.Request())
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}
	c.Response().Header().Set("Location", "/")
	return c.NoContent(http.StatusTemporaryRedirect)
}

func (a *API) setupOrLoginSocialUser(guser *goth.User, ctx httputil.RequestContext, returnUrl string) {
	exists, m, err := a.user.EmailExists(guser.Email)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		pw, err := password.Generate(64, 10, 10, false, false)
		if err != nil {
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}

		user, err := a.user.CreateAccount(guser.Email, pw, false)
		if err != nil {
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}

		err = a.user.UpdateAccountName(user.ID, user.FirstName, user.LastName)
		if err != nil {
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}
	}

	_jwt, err := a.auth.LoginID(m.ID, ctx.Request().RemoteAddr)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), _jwt)
	vals.Add("return", returnUrl)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

	http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
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
		jwt.WithModifiers(func(claims jwt2.Claims) {
			claims.(*jwt.RegisteredClaims).ExpiresAt = nil
		}),
	)
	if err != nil {
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
		return ctx.Error(errors.New("invalid key ID"), http.StatusBadRequest)
	}

	err = a.apiKey.DeleteAPIKey(user, keyID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.Error(err, http.StatusNotFound)
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

	user, err := mcontext.GetUserID(ctx.Context)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return nil
	}

	decodeToken, err := jwt.DecodeToken(token, jwt.RegisteredClaims{})
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	_uid, err := uuid.Parse(decodeToken.(*jwt.RegisteredClaims).ID)

	decodeToken, err = jwt.DecodeToken(token, jwt.RegisteredClaims{})
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	validatedKey, err := a.apiKey.ValidateAPIKey(user, _uid)
	if err != nil {
		return ctx.Error(errors.New("invalid API key"), http.StatusUnauthorized)
	}

	_jwt, err := a.auth.LoginID(validatedKey.UserID, c.Request().RemoteAddr)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	var responseDto dto.LoginResponse
	return httputil.EncodeResponse[*dto.LoginResponse](ctx, &dto.LoginResponse{Token: _jwt}, &responseDto)
}

func (a *API) deleteAccount(c echo.Context) error {
	ctx := httputil.Context(c)
	user, ok := a.getUser(ctx)

	if !ok {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	err := a.user.RequestAccountDeletion(user, ctx.Request().RemoteAddr)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			if acctErr.IsErrorType(core.ErrKeyAccountDeletionRequestAlreadyExists) {
				return ctx.Error(acctErr, acctErr.HttpStatus())
			}
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	adapter.NewMultiCookieSetter(adapter.NewFromCore(a.ctx), adapter.NewAPIProvider()).ClearJWTCookie(c.Response())
	return c.NoContent(http.StatusOK)
}

func (a *API) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	pluginCfg := a.config.GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

	corsHandler := cors.NewWithDefaults(cors.Config{})
	loginAuthMw2fa := middleware.AuthMiddleware(a.ctx, jwt.Purpose2FA)
	verifyApiKey := middleware.AuthMiddleware(a.ctx, jwt.Purpose2FA)
	authMw := middleware.AuthMiddleware(a.ctx, jwt.PurposeLogin)
	accessMw := middleware.AccessMiddleware(a.ctx)

	routes := router.DefineRoutes(
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
			router.WithAccess(""), router.WithMiddlewares(verifyApiKey),
		),
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
				router.WithResponseHeaders(http.StatusOK, "OTP verified and enabled", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/auth/otp/disable", a.otpDisable,
			router.WithSwaggerOptions(
				router.WithSummary("Disable OTP"),
				router.WithDescription("Disables 2FA for the authenticated user."),
				router.WithRequestBody(dto.OTPDisableRequest{}, "Current password", true),
				router.WithResponseHeaders(http.StatusOK, "OTP disabled", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
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
				router.WithDescription("Verifies a user's email address using a token sent via email."),
				router.WithRequestBody(dto.VerifyEmailRequest{}, "Email and verification token", true),
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
		router.NewRoute(http.MethodDelete, "/api/account/delete", a.deleteAccount,
			router.WithSwaggerOptions(
				router.WithSummary("Request account deletion"),
				router.WithDescription("Initiates the process to delete the authenticated user's account."),
				router.WithResponseHeaders(http.StatusOK, "Account deletion requested", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
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
		router.NewRoute(http.MethodGet, "/api/upload-limit", a.uploadLimit,
			router.WithSwaggerOptions(
				router.WithSummary("Get upload limit"),
				router.WithDescription("Retrieves the maximum allowed upload size."),
				router.WithResponseHeaders(http.StatusOK, "Upload limit", map[string]swagger.Schema{"application/json": {Value: dto.UploadLimitResponse{}}}, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	)

	if err := router.RegisterRoutes(gRouter, accessSvc, a.Subdomain(), routes, echo.WrapMiddleware(corsHandler)); err != nil {
		return fmt.Errorf("failed to register API routes: %w", err)
	}

	if pluginCfg.SocialLogin.Enabled {
		if err := a.setupSocialAuthRoutes(gRouter); err != nil {
			return fmt.Errorf("failed to setup social auth routes: %w", err)
		}
	}

	httpService := core.GetService[core.HTTPService](a.ctx, core.HTTP_SERVICE)
	mainRootRouter := httpService.Router()
	mainRootRouter.Use(echo.WrapMiddleware(corsHandler))

	rootRoutes := router.DefineRoutes(
		router.NewRoute(http.MethodGet, "/api/auth/complete", a.rootAuthComplete,
			router.WithSwaggerOptions(
				router.WithSummary("Authentication Complete Redirect"),
				router.WithDescription("Handles the final redirect after successful authentication (password or social). Sets authentication cookies and redirects to the return URL."),
				router.WithQueryParam("token", "Authentication token", ""),
				router.WithQueryParam("return", "URL to redirect to after completion", ""),
				router.WithResponseHeaders(http.StatusFound, "Redirecting to return URL", nil, nil),
			),
		),
	)

	if err := router.RegisterRoutes(mainRootRouter, accessSvc, "", rootRoutes); err != nil {
		return fmt.Errorf("failed to register root auth complete route: %w", err)
	}

	echoRouter := router.GetRouter(gRouter)
	if echoRouter == nil {
		panic("Underlying router is nil")
	}

	if pluginCfg.AppFolder != "" {
		// Using the new PublicFilesConfig helper
		router.MustDefaultPublicFilesSetup(gRouter, pluginCfg.AppFolder)
	} else {
		// Using the new WebAppConfig helper with embedded assets
		router.MustDefaultStaticSetup(gRouter, portal_dashboard.FS())
	}

	return nil
}

func (a *API) setupSocialAuthRoutes(gRouter router.Router) error {
	socialAuthRoutes := router.DefineRoutes(
		router.NewRoute(http.MethodGet, "/api/account/auth/sso/:provider", a.socialAuthLogin,
			router.WithSwaggerOptions(
				router.WithSummary("Initiate Social Login"),
				router.WithDescription("Redirects the user to the specified social login provider's authentication page."),
				router.WithPathParam("provider", "The social login provider (e.g., google, github)", "google"),
				router.WithQueryParam("return", "URL to redirect to after successful authentication", ""),
				router.WithResponseHeaders(http.StatusFound, "Redirecting to social login provider", nil, nil),
			),
		),
		router.NewRoute(http.MethodGet, "/api/account/auth/sso/:provider/callback", a.socialAuthCallback,
			router.WithSwaggerOptions(
				router.WithSummary("Social Login Callback"),
				router.WithDescription("Callback endpoint for social login providers. Completes the authentication process."),
				router.WithPathParam("provider", "The social login provider", "google"),
				router.WithResponseHeaders(http.StatusFound, "Redirecting to auth complete endpoint", nil, nil),
			),
		),
		router.NewRoute(http.MethodGet, "/api/account/auth/sso/:provider/logout", a.socialAuthLogout,
			router.WithSwaggerOptions(
				router.WithSummary("Social Logout"),
				router.WithDescription("Logs out the user from the social login provider session."),
				router.WithPathParam("provider", "The social login provider", "google"),
				router.WithResponseHeaders(http.StatusTemporaryRedirect, "Redirecting to home page", nil, nil),
			),
		),
	)

	if err := router.RegisterRoutes(gRouter, nil, a.Subdomain(), socialAuthRoutes); err != nil {
		return fmt.Errorf("failed to register social auth routes: %w", err)
	}

	return nil
}

func (a *API) Subdomain() string {
	return a.ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig).Subdomain
}

func (a *API) AuthTokenName() string {
	return core.AUTH_COOKIE_NAME
}

func generateSocialKey(ctx core.Context, kind string) ([]byte, error) {
	hasher := hkdf.New(sha256.New, ctx.Config().Config().Core.Identity.PrivateKey(), ctx.Config().Config().Core.NodeID.Bytes(), []byte(fmt.Sprintf("%s-%s", internal.PLUGIN_NAME, fmt.Sprintf("social-login-%s", kind))))
	derivedSeed := make([]byte, 32)

	if _, err := io.ReadFull(hasher, derivedSeed); err != nil {
		return nil, fmt.Errorf("failed to generate child key seed: %w", err)
	}

	return derivedSeed, nil
}

func loginFailed(ctx httputil.RequestContext, err error) {
	err = core.NewAccountError(core.ErrKeyInvalidLogin, err)
	_ = ctx.Error(err, http.StatusUnauthorized)
}

func accountErrorResponses(errors ...*core.AccountError) map[int]swagger.ContentValue {
	resp := make(map[int]swagger.ContentValue)
	for _, err := range errors {
		resp = router.MergeResponses(resp, router.DefineSwaggerErrorResponse(err.HttpStatus(), err))
	}
	return resp
}
