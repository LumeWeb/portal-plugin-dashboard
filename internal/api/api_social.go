package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"go.lumeweb.com/httputil"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

// publicProvider is the public metadata exposed for an enabled provider.
type publicProvider struct {
	ProviderID  string `json:"provider_id"`
	DisplayName string `json:"display_name"`
	OrderIndex  int    `json:"order_index"`
}

func (a *API) buildSocialAuthRoutes(authMw, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodGet, "/api/account/auth/providers", a.listPublicProviders,
			router.WithSwaggerOptions(
				router.WithSummary("List available social login providers"),
				router.WithDescription("Returns enabled social login providers for the login page. No authentication required."),
			),
		),
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
		router.NewRoute(http.MethodGet, "/api/account/auth/links", a.listSocialLinks,
			router.WithSwaggerOptions(
				router.WithSummary("List linked social accounts"),
				router.WithDescription("Returns the social login providers linked to the authenticated user's account."),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodPost, "/api/account/auth/sso/:provider/link", a.socialAuthLink,
			router.WithSwaggerOptions(
				router.WithSummary("Link social login provider"),
				router.WithDescription("Initiate linking a social login provider to the authenticated user. Redirects to the provider's authentication page."),
				router.WithPathParam("provider", "The social login provider (e.g., google, github)", "google"),
				router.WithQueryParam("return", "URL to redirect to after successful linking", ""),
				router.WithResponseHeaders(http.StatusFound, "Redirecting to social login provider", nil, nil),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
		router.NewRoute(http.MethodDelete, "/api/account/auth/sso/:provider", a.socialAuthUnlink,
			router.WithSwaggerOptions(
				router.WithSummary("Unlink social login provider"),
				router.WithDescription("Unlinks a social login provider from the authenticated user's account."),
				router.WithPathParam("provider", "The social login provider (e.g., google, github)", "google"),
				router.WithSuccessResponse(http.StatusNoContent, "Provider unlinked"),
			),
			router.WithAccess(core.ACCESS_USER_ROLE),
			router.WithMiddlewares(authMw, accessMw),
		),
	}
}

func (a *API) setupSocialAuthRoutes(gRouter router.Router, authMw, accessMw echo.MiddlewareFunc) error {
	socialAuthRoutes := a.buildSocialAuthRoutes(authMw, accessMw)

	if err := router.RegisterRoutes(gRouter, nil, a.Subdomain(), socialAuthRoutes); err != nil {
		return fmt.Errorf("failed to register social auth routes: %w", err)
	}

	return nil
}

// socialSessionKey returns the HMAC key used to sign the OAuth state cookie.
func (a *API) socialSessionKey() ([]byte, error) {
	return generateSocialKey(a.Context(), "session")
}

// generateRandomString produces a cryptographically random URL-safe string of
// the given byte length.
func generateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallengeS256 computes the S256 PKCE code challenge for a verifier.
func generateCodeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (a *API) socialAuthLogin(c echo.Context) error {
	ctx := httputil.Context(c)

	var req dto.SocialLoginQuery
	if _, ok := httputil.DecodeAndValidateQueryRequest[*dto.SocialLoginQuery, *dto.SocialLoginQuery](ctx, &req); !ok {
		return nil
	}

	providerName := c.Param("provider")
	returnUrl := req.ReturnURL
	if returnUrl == "" {
		returnUrl = "/"
	}

	if !a.isValidReturnURL(returnUrl) {
		return ctx.Error(errors.New("invalid return URL"), http.StatusBadRequest)
	}

	oauthProvider, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	key, err := a.socialSessionKey()
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	codeVerifier, err := generateRandomString(32)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	state, err := generateRandomString(16)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	session := &provider.SocialAuthSession{
		State:        state,
		CodeVerifier: codeVerifier,
		ReturnURL:    returnUrl,
	}

	if err := provider.SaveSession(c.Response(), session, key, a.cookieSetter(), a.Config().Config().Core.Domain); err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	authURL := oauthProvider.AuthCodeURL(state, generateCodeChallengeS256(codeVerifier))
	return c.Redirect(http.StatusFound, authURL)
}

func (a *API) socialAuthCallback(c echo.Context) error {
	ctx := httputil.Context(c)

	var req dto.SocialCallbackQuery
	if _, ok := httputil.DecodeAndValidateQueryRequest[*dto.SocialCallbackQuery, *dto.SocialCallbackQuery](ctx, &req); !ok {
		return nil
	}

	providerName := c.Param("provider")

	key, err := a.socialSessionKey()
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	session, err := provider.GetSession(c.Request(), key)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	// The session is single-use; clear it regardless of the outcome below.
	provider.ClearSession(c.Response(), a.cookieSetter(), a.Config().Config().Core.Domain)

	if req.State == "" || req.State != session.State {
		return ctx.Error(errors.New("invalid or mismatched state parameter"), http.StatusBadRequest)
	}

	if req.Error != "" {
		return ctx.Error(fmt.Errorf("provider returned error: %s", req.Error), http.StatusBadRequest)
	}

	if req.Code == "" {
		return ctx.Error(errors.New("missing authorization code"), http.StatusBadRequest)
	}

	oauthProvider, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	user, err := oauthProvider.Exchange(c.Request().Context(), req.Code, session.CodeVerifier)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if session.Mode == provider.SessionModeLink {
		return a.completeSocialLink(ctx, providerName, session, user)
	}

	return a.finishSocialLogin(ctx, providerName, user, session.ReturnURL)
}

// listSocialLinks returns the social accounts linked to the authenticated user.
func (a *API) listSocialLinks(c echo.Context) error {
	ctx := httputil.Context(c)

	userId, err := mcontext.GetUserID(ctx.Context)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	accounts, err := a.socialAuth.ListAccounts(ctx.Request().Context(), userId)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	links := make([]dto.SocialAccountResponse, 0, len(accounts))
	for _, acct := range accounts {
		links = append(links, dto.SocialAccountResponse{
			Provider:       acct.Provider,
			ProviderUserID: acct.ProviderUserID,
			Email:          acct.Email,
			CreatedAt:      acct.CreatedAt,
		})
	}

	return ctx.JSON(http.StatusOK, links)
}

// socialAuthLink initiates linking a provider to the authenticated user. It
// records the link mode and user id in the signed session, then redirects to
// the provider.
func (a *API) socialAuthLink(c echo.Context) error {
	ctx := httputil.Context(c)

	var req dto.SocialLoginQuery
	if _, ok := httputil.DecodeAndValidateQueryRequest[*dto.SocialLoginQuery, *dto.SocialLoginQuery](ctx, &req); !ok {
		return nil
	}

	providerName := c.Param("provider")
	returnUrl := req.ReturnURL
	if returnUrl == "" {
		returnUrl = "/"
	}
	if !a.isValidReturnURL(returnUrl) {
		return ctx.Error(errors.New("invalid return URL"), http.StatusBadRequest)
	}

	userId, err := mcontext.GetUserID(ctx.Context)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	oauthProvider, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		return ctx.Error(err, http.StatusBadRequest)
	}

	key, err := a.socialSessionKey()
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	codeVerifier, err := generateRandomString(32)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	state, err := generateRandomString(16)
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	session := &provider.SocialAuthSession{
		State:        state,
		CodeVerifier: codeVerifier,
		ReturnURL:    returnUrl,
		Mode:         provider.SessionModeLink,
		UserID:       userId,
	}

	if err := provider.SaveSession(c.Response(), session, key, a.cookieSetter(), a.Config().Config().Core.Domain); err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	authURL := oauthProvider.AuthCodeURL(state, generateCodeChallengeS256(codeVerifier))
	return c.Redirect(http.StatusFound, authURL)
}

// completeSocialLink links a provider identity to the user recorded in the
// link session, then redirects back to the return URL.
func (a *API) completeSocialLink(ctx httputil.RequestContext, providerName string, session *provider.SocialAuthSession, user *provider.OAuth2User) error {
	if session.UserID == 0 {
		return ctx.Error(errors.New("invalid link session"), http.StatusBadRequest)
	}

	if err := a.socialAuth.LinkAccount(ctx.Request().Context(), session.UserID, providerName, user.ProviderUserID, user.Email); err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	target := session.ReturnURL
	if target == "" {
		target = "/"
	}
	http.Redirect(ctx.Response(), ctx.Request(), target, http.StatusFound)
	return nil
}

// socialAuthUnlink removes a provider link from the authenticated user.
func (a *API) socialAuthUnlink(c echo.Context) error {
	ctx := httputil.Context(c)

	providerName := c.Param("provider")

	userId, err := mcontext.GetUserID(ctx.Context)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	if err := a.socialAuth.UnlinkAccount(ctx.Request().Context(), userId, providerName); err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (a *API) finishSocialLogin(ctx httputil.RequestContext, providerName string, user *provider.OAuth2User, returnUrl string) error {
	result, err := a.socialAuth.LoginOrLink(
		ctx.Request().Context(),
		providerName,
		user.ProviderUserID,
		user.Email,
		user.EmailVerified,
	)
	if err != nil {
		// A verified email that already belongs to a user means the person owns
		// both identities: link the SSO identity to the existing account and log
		// them in. Unverified emails keep the conflict rejection.
		if user.EmailVerified && core.IsAccountError(err) &&
			core.AsAccountError(err).IsErrorType(core.ErrKeySocialEmailConflict) {
			userId, ok, linkErr := a.autoLinkOnVerifiedConflict(ctx, providerName, user)
			if linkErr != nil {
				return a.socialError(ctx, linkErr)
			}
			if ok {
				return a.loginAndRedirect(ctx, userId, returnUrl)
			}
		}
		return a.socialError(ctx, err)
	}

	// If the provider did not confirm the email, the account is created
	// unverified and must be verified before a session is established.
	if !result.EmailVerified {
		if err := a.user.SendEmailVerification(ctx.Request().Context(), result.User.ID); err != nil && !core.IsAccountError(err) {
			a.Logger().Warn("failed to send email verification", zap.Error(err))
		}
		http.Redirect(ctx.Response(), ctx.Request(), "/verify-email", http.StatusFound)
		return nil
	}

	return a.loginAndRedirect(ctx, result.User.ID, returnUrl)
}

// autoLinkOnVerifiedConflict links the SSO identity to the existing account
// that already holds the email and returns that account's id. It is only safe
// because it runs after the provider confirmed the email. A lookup failure
// falls through (ok=false) so the caller keeps the original conflict error.
func (a *API) autoLinkOnVerifiedConflict(ctx httputil.RequestContext, providerName string, user *provider.OAuth2User) (uint, bool, error) {
	exists, existing, err := a.user.EmailExists(ctx.Request().Context(), user.Email)
	if err != nil || !exists {
		return 0, false, nil
	}

	if err := a.socialAuth.LinkAccount(ctx.Request().Context(), existing.ID, providerName, user.ProviderUserID, user.Email); err != nil {
		return 0, false, err
	}

	return existing.ID, true, nil
}

// loginAndRedirect establishes a session for the user and redirects to the
// auth-complete endpoint.
func (a *API) loginAndRedirect(ctx httputil.RequestContext, userID uint, returnUrl string) error {
	_jwt, err := a.auth.LoginID(ctx.Request().Context(), userID, ctx.RealIP(), false)
	if err != nil {
		return a.socialError(ctx, err)
	}

	redirectURL := a.buildAuthCompleteURL(_jwt, returnUrl)
	http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
	return nil
}

// socialError maps an account error to its HTTP status, else a 500.
func (a *API) socialError(ctx httputil.RequestContext, err error) error {
	if core.IsAccountError(err) {
		acctErr := core.AsAccountError(err)
		return ctx.Error(acctErr, acctErr.HttpStatus())
	}
	return ctx.Error(err, http.StatusInternalServerError)
}

func (a *API) socialAuthLogout(c echo.Context) error {
	ctx := httputil.Context(c)

	provider.ClearSession(c.Response(), a.cookieSetter(), a.Config().Config().Core.Domain)

	c.Response().Header().Set("Location", "/")
	return ctx.NoContent(http.StatusTemporaryRedirect)
}

// listPublicProviders returns enabled social login providers for the login
// page. Only public metadata is exposed; secrets are never returned.
func (a *API) listPublicProviders(c echo.Context) error {
	var configs []pluginDb.SocialProviderConfig
	if err := a.DB().Where("enabled = ?", true).Order("order_index ASC, display_name ASC").Find(&configs).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list providers"})
	}

	providers := make([]publicProvider, 0, len(configs))
	for _, cfg := range configs {
		providers = append(providers, publicProvider{
			ProviderID:  cfg.ProviderID,
			DisplayName: cfg.DisplayName,
			OrderIndex:  cfg.OrderIndex,
		})
	}

	return c.JSON(http.StatusOK, providers)
}

// isValidReturnURL checks if a return URL is a same-site relative path.
// Returns true for paths starting with "/" but not "//", false otherwise.
func (a *API) isValidReturnURL(returnUrl string) bool {
	if returnUrl == "" {
		return false
	}

	// Must start with "/" but not "//" to be a relative path
	if !strings.HasPrefix(returnUrl, "/") || strings.HasPrefix(returnUrl, "//") {
		return false
	}

	// Must not be an absolute URL
	if strings.Contains(returnUrl, "://") {
		return false
	}

	return true
}
