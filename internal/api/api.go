package api

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.lumeweb.com/portal-middleware/middleware"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal/service"
	_ "golang.org/x/image/webp"

	"github.com/labstack/echo/v4"
	swagger "go.lumeweb.com/gswagger"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	_ "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/event"
	portal_dashboard "go.lumeweb.com/web/go/portal-dashboard"
	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
)

const (
	AuthCompletePath = "/api/auth/complete" // Path for authentication complete endpoint
	RememberMeCookie = "remember_me"        // Cookie name for remember me flag
)

var _ core.API = (*API)(nil)

type API struct {
	*core.BaseComponent
	user           core.UserService
	auth           core.AuthService
	password       core.PasswordResetService
	otp            core.OTPService
	apiKey         pluginCore.APIKeyService
	access         core.AccessService
	http           core.HTTPService
	requestSvc     core.RequestService
	workflowSvc    core.WorkflowService
	ops            core.OperationFinder
	socialAuth     core.SocialAuthService
	socialProvider pluginCore.SocialProviderService
	providerStore  *provider.ProviderStore
}

func (a *API) ID() string {
	return a.Name()
}

func (a *API) OpenAPIInfo() router.APIInfoDefinition {
	// Implement the OpenAPIInfo method using the router.APIInfo builder
	return router.APIInfo().
		Title("Account API").Description("API endpoints for managing user accounts, authentication, and API keys.")
}

func (a *API) GetConfig() config.APIConfig {
	return &pluginConfig.APIConfig{}
}

func (a *API) Name() string {
	return "dashboard"
}

func NewAPI() (core.API, []core.ContextBuilderOption, error) {
	api := &API{}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			// Get services using GetServiceOptional to avoid fatal errors in tests
			// Then check if we got the right types
			api.user = core.GetServiceOptional[core.UserService](ctx, core.USER_SERVICE)
			api.auth = core.GetServiceOptional[core.AuthService](ctx, core.AUTH_SERVICE)
			api.password = core.GetServiceOptional[core.PasswordResetService](ctx, core.PASSWORD_RESET_SERVICE)
			api.otp = core.GetServiceOptional[core.OTPService](ctx, core.OTP_SERVICE)
			api.apiKey = core.GetServiceOptional[pluginCore.APIKeyService](ctx, pluginCore.API_KEY_SERVICE)
			api.access = core.GetServiceOptional[core.AccessService](ctx, core.ACCESS_SERVICE)
			// Logger is provided by BaseComponent via ContextWithStartupComponent
			api.http = ctx.Service(core.HTTP_SERVICE).(core.HTTPService)
			api.requestSvc = ctx.Service(core.REQUEST_SERVICE).(core.RequestService)
			api.workflowSvc = ctx.Service(core.WORKFLOW_SERVICE).(core.WorkflowService)
			api.ops = service.NewOperationFinder(ctx)

			return nil
		}),
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			event.OnBootCompleted(ctx, func(ctx core.Context, eventCtx context.Context) error {
				return core.Fire(ctx, event.EVENT_USER_SERVICE_SUBDOMAIN_SET, event.NewUserServiceSubdomainSetEvent(api.Subdomain(), eventCtx))
			})
			return nil
		}),

		core.ContextWithStartupFunc(func(ctx core.Context) error {
			api.socialAuth = core.GetServiceOptional[core.SocialAuthService](ctx, core.SOCIAL_AUTH_SERVICE)
			api.socialProvider = core.GetServiceOptional[pluginCore.SocialProviderService](ctx, pluginCore.SOCIAL_PROVIDER_SERVICE)

			pluginCfg := ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

			if pluginCfg.SocialLogin.Enabled {
				api.providerStore = provider.Provider()
				api.providerStore.SetContext(ctx)
				if err := api.providerStore.LoadFromDB(ctx.DB()); err != nil {
					return err
				}
			}

			return nil
		}),
	)

	return api, opts, nil
}

func (a *API) ping(c echo.Context) error {
	ctx := httputil.Context(c)

	token, ok := a.getAuthToken(ctx)

	if !ok {
		return nil
	}

	a.cookieSetter().EchoAuthCookie(c.Response(), c.Request())
	jwt.SendHeader(c.Response(), token)

	response := &dto.PongResponse{
		Ping:  "pong",
		Token: token,
	}
	return httputil.EncodeResponse(ctx, response, response)
}

func (a *API) cookieSetter() adapter.CookieSetter {
	return adapter.NewMultiCookieSetter(adapter.NewFromCore(a.Context()), adapter.NewAPIProvider())
}

func (a *API) setAuthCookie(c echo.Context, token string) error {
	return a.setAuthCookieWithRemember(c, token, false)
}

func (a *API) setAuthCookieWithRemember(c echo.Context, token string, remember bool) error {
	decodeToken, err := jwt.DecodeToken(token, &jwt.RegisteredClaims{})
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}

	sub, err := decodeToken.GetSubject()
	if err != nil {
		return fmt.Errorf("failed to get subject from token: %w", err)
	}
	if sub == "" {
		return errors.New("token subject claim is empty")
	}

	aud, err := decodeToken.GetAudience()
	if err != nil {
		return fmt.Errorf("failed to get audience from token: %w", err)
	}
	if len(aud) == 0 {
		return errors.New("token audience claim is missing")
	}

	exp, err := decodeToken.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("failed to get expiration time from token: %w", err)
	}
	if exp == nil {
		return errors.New("token expiration claim is missing")
	}

	ttl := time.Until(exp.Time)
	if ttl <= 0 {
		return errors.New("token is expired")
	}

	// If remember is true, don't let cookie TTL exceed token exp to avoid drift
	if remember {
		if rttl := time.Duration(a.Config().Config().Core.Account.RememberMeTTL) * time.Second; rttl < ttl {
			ttl = rttl
		}
	}

	_, err = a.cookieSetter().SetJWTCookie(c.Response(), sub, jwt.Purpose(aud[0]), ttl)
	return err
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

	exists, user, err := a.user.AccountExists(ctx.Request().Context(), userId)
	if err != nil {
		a.Logger().Error("failed to check if email exists", zap.Error(err))
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if !exists {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	returnUrl := c.QueryParam("return")

	// Retrieve the remember flag from cookies
	remember := a.getRememberFlagFromCookie(ctx)

	// Set the authentication cookie with the remember flag
	if err := a.setAuthCookieWithRemember(c, token, remember); err != nil {
		loginFailed(ctx, err)
		return nil
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

func (a *API) logout(c echo.Context) error {
	a.cookieSetter().ClearJWTCookie(c.Response())

	// Clear the remember-me cookie to prevent preference bleed
	a.clearRememberMeCookie(c)

	return c.NoContent(http.StatusOK)
}

func (a *API) uploadLimit(c echo.Context) error {
	ctx := httputil.Context(c)
	responseModel := &dto.UploadLimitResponse{
		Limit: a.Config().Config().Core.PostUploadLimit,
	}
	var responseDto dto.UploadLimitResponse
	return httputil.EncodeResponse[*dto.UploadLimitResponse](ctx, responseModel, &responseDto)
}

func (a *API) getUser(ctx httputil.RequestContext) (uint, bool) {
	user, err := mcontext.GetUserID(ctx.Context)
	if err != nil {
		return 0, false
	}
	return user, true
}

// extractAuthToken extracts the raw auth token from the request.
// First checks the request context (set by auth middleware), then falls back to
// reading the Authorization header directly for public endpoints like /api/auth/key.
// It does NOT write responses or validate the token - that's the caller's responsibility.
func (a *API) extractAuthToken(ctx httputil.RequestContext) (string, error) {
	// Try context first (for middleware-set tokens from authenticated requests)
	token, err := mcontext.GetAuthToken(ctx.Context)
	if err == nil && token != "" {
		return token, nil
	}

	// Fall back to reading Authorization header directly (for public endpoints)
	// Use the helper from auth middleware which handles Bearer/bearer prefixes
	authToken := auth.ParseAuthTokenHeader(ctx.Request().Header)
	if authToken == "" {
		return "", errors.New("missing authorization header")
	}

	return authToken, nil
}

// getAuthToken extracts and validates the auth token, writing an error response if missing.
// This returns (token, ok) for backward compatibility with existing code.
// DEPRECATED: Use extractAuthToken and handle errors explicitly in new code.
func (a *API) getAuthToken(ctx httputil.RequestContext) (string, bool) {
	token, err := a.extractAuthToken(ctx)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return "", false
	}

	return token, true
}

// getRememberFlagFromCookie retrieves the remember flag from a cookie
func (a *API) getRememberFlagFromCookie(ctx httputil.RequestContext) bool {
	cookie, err := ctx.Request().Cookie(RememberMeCookie)
	if err != nil {
		return false
	}
	return cookie.Value == "true"
}

// storeRememberFlagInCookie stores the remember flag in a cookie
func (a *API) storeRememberFlagInCookie(c echo.Context, remember bool) {
	cookieSetter := a.cookieSetter()
	rememberValue := "false"
	if remember {
		rememberValue = "true"
	}

	// Set cookie for the configured TTL if remember is true, otherwise expire immediately
	expiry := time.Now().Add(time.Duration(a.Config().Config().Core.Account.RememberMeTTL) * time.Second)
	if !remember {
		expiry = time.Now().Add(-1 * time.Hour) // Expire immediately
	}

	cookieSetter.SetCookie(
		c.Response(),
		RememberMeCookie,
		rememberValue,
		a.Config().Config().Core.Domain,
		"/",
		expiry,
		true,
		true,
		http.SameSiteStrictMode,
	)
}

// clearRememberMeCookie clears the remember-me cookie to prevent preference bleed
func (a *API) clearRememberMeCookie(c echo.Context) {
	a.storeRememberFlagInCookie(c, false)
}

func (a *API) Subdomain() string {
	return core.GetAPIConfig[*pluginConfig.APIConfig](a.Context(), internal.PLUGIN_NAME).Subdomain
}

func (a *API) S3Bucket() string {
	return a.Config().Config().Core.Storage.S3.BufferBucket
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

func accountErrorResponses(errors ...*core.Error) map[int]swagger.ContentValue {
	resp := make(map[int]swagger.ContentValue)
	for _, err := range errors {
		resp = router.MergeResponses(resp, router.DefineSwaggerErrorResponse(err.HttpStatus(), err))
	}
	return resp
}

func (a *API) buildAuthCompleteURL(token string, returnURL string) string {
	cfg := a.Context().Config().Config().Core

	// Determine effective port (prefer externalPort if set)
	port := cfg.ExternalPort
	if port == 0 {
		port = cfg.Port
	}

	// Build host with port if needed
	host := cfg.Domain
	if port != 0 && port != 443 && port != 80 {
		host = fmt.Sprintf("%s:%d", host, port)
	}

	// Use scheme from request
	scheme := "http"
	if cfg.Secure {
		scheme = "https"
	}

	// Validate and sanitize returnURL if provided
	var sanitizedReturn string
	if returnURL != "" {
		if parsedURL, err := url.Parse(returnURL); err == nil {
			// Only allow relative paths or same-origin URLs
			if parsedURL.Host == "" || parsedURL.Host == host {
				sanitizedReturn = parsedURL.String()
			}
		}
	}

	// Build URL with query params
	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   AuthCompletePath,
	}

	query := url.Values{}
	if token != "" {
		query.Set(a.AuthTokenName(), token) // Use configured auth token name
	}
	if sanitizedReturn != "" {
		query.Set("return", sanitizedReturn)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	return u.String()
}

func (a *API) Configure(gRouter router.Router, accessSvc core.AccessService) error {
	pluginCfg := a.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

	// Create middleware instances once
	authMw := middleware.AuthMiddleware(a.Context(), middleware.WithAuthPurpose(jwt.PurposeLogin))
	loginAuthMw2fa := middleware.AuthMiddleware(a.Context(), middleware.WithAuthPurpose(jwt.Purpose2FA))
	accessMw := middleware.AccessMiddleware(a.Context())

	// Build all routes
	var routes []router.Route

	// Add auth routes
	routes = append(routes, a.buildAuthRoutes(authMw, loginAuthMw2fa, accessMw)...)

	// Add key identity routes (challenge + verify)
	routes = append(routes, a.buildKeyIdentityRoutes()...)

	// Add key identity management routes (authenticated)
	routes = append(routes, a.buildKeyIdentityManageRoutes(authMw, accessMw)...)

	// Add account routes
	routes = append(routes, a.buildAccountRoutes(authMw, accessMw)...)

	// Add API key routes
	routes = append(routes, a.buildAPIKeyRoutes(authMw, accessMw)...)

	// Add avatar routes
	routes = append(routes, a.buildAvatarRoutes(authMw, accessMw)...)

	// Add OTP routes
	routes = append(routes, a.buildOTPRoutes(authMw, loginAuthMw2fa, accessMw)...)

	// Add operation routes
	routes = append(routes, a.buildOperationRoutes(authMw, accessMw)...)

	// Add upload limit route
	routes = append(routes, router.NewRoute(http.MethodGet, "/api/upload-limit", a.uploadLimit,
		router.WithSwaggerOptions(
			router.WithSummary("Get upload limit"),
			router.WithDescription("Retrieves the maximum allowed upload size."),
			router.WithResponseHeaders(http.StatusOK, "Upload limit", map[string]swagger.Schema{"application/json": {Value: dto.UploadLimitResponse{}}}, nil),
		),
	))

	if err := router.RegisterRoutes(gRouter, accessSvc, a.Subdomain(), routes, router.WithCors()); err != nil {
		return fmt.Errorf("failed to register API routes: %w", err)
	}

	if pluginCfg.SocialLogin.Enabled {
		if err := a.setupSocialAuthRoutes(gRouter, authMw, accessMw); err != nil {
			return fmt.Errorf("failed to setup social auth routes: %w", err)
		}
	}

	mainRootRouter := a.http.Router()

	rootRoutes := a.buildRootAuthCompleteRoute()
	if err := router.RegisterRoutes(mainRootRouter, accessSvc, "", rootRoutes, router.WithCors()); err != nil {
		return fmt.Errorf("failed to register root auth complete route: %w", err)
	}

	err := a.http.RegisterGlobalPath("/api/auth/complete")
	if err != nil {
		return fmt.Errorf("failed to register global path: %w", err)
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
		fsConfig := router.AppFilesystemConfig{Domain: a.Config().Config().Core.Domain}
		if pluginCfg.Branding.LogoURL != "" || pluginCfg.Branding.FaviconURL != "" {
			brand, _ := json.Marshal(pluginCfg.Branding)
			fsConfig.BrandJSON = string(brand)
		}
		router.MustDefaultStaticSetup(gRouter, router.NewAppFilesystem(portal_dashboard.GetFS(), fsConfig))
	}

	return nil
}
