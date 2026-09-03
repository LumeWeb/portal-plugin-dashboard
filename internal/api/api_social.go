package api

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"go.lumeweb.com/httputil"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db/models"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/queryutil"
	queryutilHttp "go.lumeweb.com/queryutil/http"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// socialConsentPageData carries the data rendered into the link-consent page:
// the provider a user wants to link and the email address the link resolves
// to. The provider user id and session state are never rendered; they live in
// the HMAC-signed consent session.
type socialConsentPageData struct {
	ProviderName string
	Email        string
}

// socialLayoutData is the shared layout wrapper for the embedded HTML
// templates, mirroring the portal-plugin-mcp consent page.
type socialLayoutData struct {
	AriaLabelledBy  string
	AriaDescribedBy string
	MetaDescription string
	PageData        any
}

//go:embed social_layout.html
var socialLayoutHTML string

//go:embed social_consent.html
var socialConsentHTML string

//go:embed social_error.html
var socialErrorHTML string

type socialErrorPageData struct {
	Heading     string
	Message     string
	ActionURL   string
	ActionLabel string
}

var socialConsentTemplate *template.Template
var socialErrorTemplate *template.Template

func init() {
	socialConsentTemplate = template.Must(template.New("social-consent").
		Parse(socialLayoutHTML))
	template.Must(socialConsentTemplate.New("page").Parse(socialConsentHTML))
	template.Must(socialConsentTemplate.Parse(`{{define "consent"}}{{template "layout" .}}{{end}}`))

	socialErrorTemplate = template.Must(template.New("social-error").
		Parse(socialLayoutHTML))
	template.Must(socialErrorTemplate.New("page").Parse(socialErrorHTML))
	template.Must(socialErrorTemplate.Parse(`{{define "error"}}{{template "layout" .}}{{end}}`))
}

func (a *API) buildSocialAuthRoutes(authMw, accessMw echo.MiddlewareFunc) []router.Route {
	return []router.Route{
		router.NewRoute(http.MethodGet, "/api/account/auth/providers", a.listPublicProviders,
			router.WithSwaggerOptions(
				router.WithSummary("List available social login providers"),
				router.WithDescription("Returns enabled social login providers for the login page. No authentication required."),
				router.WithSuccessResponse(http.StatusOK, "Enabled social login providers",
					router.WithJSONContent([]dto.PublicProviderResponse{})),
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
				router.WithSuccessResponse(http.StatusOK, "Paginated list of linked social accounts",
					router.WithJSONContent(dto.SocialAccountListResponse{}),
					router.WithTotalCountHeader()),
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
		router.NewRoute(http.MethodGet, "/api/account/auth/sso/:provider/consent", a.socialConsentPage,
			router.WithSwaggerOptions(
				router.WithSummary("Show social link consent page"),
				router.WithDescription("Renders the consent page when a verified social login email matches an existing account. The page asks the user to approve linking the provider identity to that account before any link is created."),
				router.WithPathParam("provider", "The social login provider (e.g., google, github)", "google"),
				router.WithSuccessResponse(http.StatusOK, "Consent page (text/html)"),
			),
		),
		router.NewRoute(http.MethodPost, "/api/account/auth/sso/:provider/consent", a.socialConsentSubmit,
			router.WithSwaggerOptions(
				router.WithSummary("Approve or reject social link consent"),
				router.WithDescription("Approves or rejects linking the pending provider identity to the existing account. Called by the consent page. Returns the redirect URI to navigate to."),
				router.WithPathParam("provider", "The social login provider (e.g., google, github)", "google"),
				router.WithRequestBody(struct {
					Approve bool `json:"approve"`
				}{}, "Approval decision", true),
				router.WithSuccessResponse(http.StatusOK, "Redirect URI", router.WithJSONContent(dto.SocialConsentResponse{})),
			),
			router.WithMiddlewares(a.verifySameOrigin()),
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
		apiErr := NewError(ErrKeyInvalidReturnURL, nil)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	oauthProvider, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		apiErr := NewError(ErrKeyProviderNotEnabled, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	key, err := a.socialSessionKey()
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	codeVerifier, err := generateRandomString(32)
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	state, err := generateRandomString(16)
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	session := &provider.SocialAuthSession{
		State:        state,
		CodeVerifier: codeVerifier,
		ReturnURL:    returnUrl,
	}

	if err := provider.SaveSession(c.Response(), session, key, a.cookieSetter(), a.Config().Config().Core.Domain); err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
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

	// This endpoint is only ever navigated by the browser (the provider's
	// redirect lands here), so every failure surfaces as the styled sign-in
	// error screen instead of a raw JSON body. Errors that carry details
	// (token exchange failures) are logged above; the page stays generic.
	key, err := a.socialSessionKey()
	if err != nil {
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyInternalError, err))
	}

	session, err := provider.GetSession(c.Request(), key)
	if err != nil {
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyInternalError, err))
	}

	// The session is single-use; clear it regardless of the outcome below.
	provider.ClearSession(c.Response(), a.cookieSetter(), a.Config().Config().Core.Domain)

	if req.State == "" || req.State != session.State {
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyInvalidState, nil))
	}

	if req.Error != "" {
		// The provider never sends an error code with a usable session; log it
		// for support but keep the user on a generic screen.
		ctx.Logger().Warn("social provider returned an error at callback",
			zap.String("provider", providerName),
			zap.String("reason", req.Error))
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyProviderError, nil, req.Error))
	}

	if req.Code == "" {
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyMissingAuthCode, nil))
	}

	oauthProvider, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyProviderNotEnabled, err))
	}

	user, err := oauthProvider.Exchange(c.Request().Context(), req.Code, session.CodeVerifier)
	if err != nil {
		// The API error body is generic by design; log the sanitized failure
		// reason here so ops can tell an invalid client secret
		// (invalid_client), a host/scheme mismatch (redirect_uri_mismatch), or
		// a replayed/bad verifier (invalid_grant) apart in logs.
		//
		// RetrieveError.Error() embeds the raw token-endpoint response body
		// when Google's response omits the RFC 6749 error field, so only its
		// structured, body-free fields are persisted at WARN; anything else in
		// the chain (transport failures, userinfo claim errors) is PII-free.
		reason := err.Error()
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			reason = fmt.Sprintf("%s: %s: %s", re.ErrorCode, re.ErrorDescription, re.ErrorURI)
		}
		ctx.Logger().Warn("social auth code exchange failed",
			zap.String("provider", providerName),
			zap.String("reason", reason))
		return a.socialErrorPage(ctx, providerName, NewError(ErrKeyProviderExchangeFailed, err))
	}

	if session.Mode == provider.SessionModeLink {
		return a.completeSocialLink(ctx, providerName, session, user)
	}

	return a.finishSocialLogin(ctx, providerName, user, session.ReturnURL)
}

// listSocialLinks returns the social accounts linked to the authenticated
// user, using the standard queryutil list API (filters/sorts/pagination).
func (a *API) listSocialLinks(c echo.Context) error {
	ctx := httputil.Context(c)

	userId, err := mcontext.GetUserID(ctx.Context)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	return queryutilHttp.ProcessListRequest(
		c.Response(),
		c.Request(),
		"social_accounts",
		func(filters []queryutil.CrudFilter, sorts []queryutil.Sort, pagination queryutil.Pagination) ([]*models.SocialAccount, int64, error) {
			return a.socialAuth.ListAccounts(ctx.Request().Context(), userId, filters, sorts, pagination)
		},
		func(acct *models.SocialAccount) dto.SocialAccountResponse {
			return dto.SocialAccountResponse{
				Provider:       acct.Provider,
				ProviderUserID: acct.ProviderUserID,
				Email:          acct.Email,
				CreatedAt:      acct.CreatedAt,
			}
		},
	)
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
		apiErr := NewError(ErrKeyInvalidReturnURL, nil)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	userId, err := mcontext.GetUserID(ctx.Context)
	if err != nil {
		return ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
	}

	oauthProvider, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		apiErr := NewError(ErrKeyProviderNotEnabled, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	key, err := a.socialSessionKey()
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	codeVerifier, err := generateRandomString(32)
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	state, err := generateRandomString(16)
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	session := &provider.SocialAuthSession{
		State:        state,
		CodeVerifier: codeVerifier,
		ReturnURL:    returnUrl,
		Mode:         provider.SessionModeLink,
		UserID:       userId,
	}

	if err := provider.SaveSession(c.Response(), session, key, a.cookieSetter(), a.Config().Config().Core.Domain); err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	authURL := oauthProvider.AuthCodeURL(state, generateCodeChallengeS256(codeVerifier))
	return c.Redirect(http.StatusFound, authURL)
}

// completeSocialLink links a provider identity to the user recorded in the
// link session, then redirects back to the return URL.
func (a *API) completeSocialLink(ctx httputil.RequestContext, providerName string, session *provider.SocialAuthSession, user *provider.OAuth2User) error {
	if session.UserID == 0 {
		apiErr := NewError(ErrKeyInvalidLinkSession, nil)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	if err := a.socialAuth.LinkAccount(ctx.Request().Context(), session.UserID, providerName, user.ProviderUserID, user.Email); err != nil {
		return a.socialErrorPage(ctx, providerName, err)
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
		// both identities. The identity is NOT linked silently: the user must
		// confirm on a consent page first (a provider misreporting email
		// verification must not let anyone take over an existing account).
		// Unverified emails keep the conflict rejection, shown as an error
		// screen explaining how to link the provider from account settings.
		if user.EmailVerified && core.IsAccountError(err) &&
			core.AsAccountError(err).IsErrorType(core.ErrKeySocialEmailConflict) {
			if ok, promptErr := a.promptLinkConsent(ctx, providerName, user, returnUrl); promptErr != nil {
				return a.socialErrorPage(ctx, providerName, promptErr)
			} else if ok {
				return nil
			}
			// ok=false: the email no longer maps to an account, so the
			// original conflict stands — rendered as the error screen.
		}
		return a.socialErrorPage(ctx, providerName, err)
	}

	// If the provider did not confirm the email, the account is created
	// unverified and must be verified before a session is established.
	if !result.EmailVerified {
		if err := a.user.SendEmailVerification(ctx.Request().Context(), result.User.ID); err != nil {
			return a.socialErrorPage(ctx, providerName, err)
		}
		http.Redirect(ctx.Response(), ctx.Request(), "/account/verify", http.StatusFound)
		return nil
	}

	return a.loginAndRedirect(ctx, providerName, result.User.ID, returnUrl)
}

// promptLinkConsent handles a verified-email conflict during login by parking
// the provider identity in a signed consent session and redirecting to the
// consent page. No account link happens until the user approves. The conflict
// is re-verified against the current account for that email; ok=false falls
// through so the caller keeps the original conflict error.
func (a *API) promptLinkConsent(ctx httputil.RequestContext, providerName string, user *provider.OAuth2User, returnUrl string) (bool, error) {
	exists, _, err := a.user.EmailExists(ctx.Request().Context(), user.Email)
	if err != nil || !exists {
		return false, nil
	}

	key, err := a.socialSessionKey()
	if err != nil {
		return false, err
	}

	session := &provider.SocialAuthSession{
		Mode:           provider.SessionModeConsentLink,
		ReturnURL:      returnUrl,
		ProviderName:   providerName,
		ProviderUserID: user.ProviderUserID,
		Email:          user.Email,
	}
	if err := provider.SaveSession(ctx.Response(), session, key, a.cookieSetter(), a.Config().Config().Core.Domain); err != nil {
		return false, err
	}

	http.Redirect(ctx.Response(), ctx.Request(), socialConsentPath(providerName), http.StatusFound)
	return true, nil
}

// socialConsentPage renders the link-consent page. The consent-mode session
// cookie is the credential: it is HMAC-signed, single-use, and short-lived, so
// the page only renders for a real, in-flight identity merge. A missing or
// mismatched session redirects home.
func (a *API) socialConsentPage(c echo.Context) error {
	ctx := httputil.Context(c)

	key, err := a.socialSessionKey()
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}
	session, err := provider.GetSession(c.Request(), key)
	if err != nil || session.Mode != provider.SessionModeConsentLink ||
		session.ProviderName == "" || session.ProviderUserID == "" || session.Email == "" {
		return c.Redirect(http.StatusFound, "/")
	}

	displayName := a.providerDisplayName(ctx, session.ProviderName)
	// Content-Type must be set before ExecuteTemplate writes the body.
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return socialConsentTemplate.ExecuteTemplate(c.Response().Writer, "consent", socialLayoutData{
		AriaLabelledBy:  "consent-heading",
		AriaDescribedBy: "consent-description",
		MetaDescription: "Link your social account",
		PageData: socialConsentPageData{
			ProviderName: displayName,
			Email:        session.Email,
		},
	})
}

// socialConsentSubmit processes the consent page approve/reject. The POST is
// guarded against CSRF by a same-origin check; the browser's consent page
// submits with a same-origin fetch, so a genuine approval always carries a
// matching Origin. On approve the identity is linked to the account that
// currently holds the email and the user is logged in; on reject the pending
// session is cleared. Both cases return the next redirect URI as JSON.
func (a *API) socialConsentSubmit(c echo.Context) error {
	ctx := httputil.Context(c)

	var req dto.SocialConsentRequest
	if _, ok := httputil.DecodeAndValidateRequest[*dto.SocialConsentRequest, *dto.SocialConsentRequest](ctx, &req); !ok {
		return nil // Error handled by DecodeAndValidateRequest
	}

	key, err := a.socialSessionKey()
	if err != nil {
		apiErr := NewError(ErrKeyInternalError, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}
	session, err := provider.GetSession(c.Request(), key)
	if err != nil || session.Mode != provider.SessionModeConsentLink ||
		session.ProviderName == "" || session.ProviderUserID == "" || session.Email == "" {
		// Expired or forged consent: clear whatever cookie is present and send
		// the user home. A redirect payload (not a canonical error body) lets
		// the consent page navigate away instead of stranding the user on an
		// error with no way back.
		provider.ClearSession(c.Response(), a.cookieSetter(), a.Config().Config().Core.Domain)
		return c.JSON(http.StatusBadRequest, dto.SocialConsentResponse{RedirectURI: "/"})
	}
	// Single-use: the pending identity cannot be approved twice.
	provider.ClearSession(c.Response(), a.cookieSetter(), a.Config().Config().Core.Domain)

	if !req.Approve {
		responseModel := &dto.SocialConsentResponse{RedirectURI: "/"}
		var responseDto dto.SocialConsentResponse
		return httputil.EncodeResponse(ctx, responseModel, &responseDto)
	}

	exists, existing, err := a.user.EmailExists(ctx.Request().Context(), session.Email)
	if err != nil || !exists {
		// The email no longer maps to an account; send the user home.
		return c.JSON(http.StatusBadRequest, dto.SocialConsentResponse{RedirectURI: "/"})
	}

	if err := a.socialAuth.LinkAccount(ctx.Request().Context(), existing.ID, session.ProviderName, session.ProviderUserID, session.Email); err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			return ctx.Error(acctErr, acctErr.HttpStatus())
		}
		return ctx.Error(err, http.StatusInternalServerError)
	}

	redirectURI, err := a.loginRedirectURI(ctx, existing.ID, session.ReturnURL)
	if err != nil {
		return a.socialError(ctx, err)
	}

	responseModel := &dto.SocialConsentResponse{RedirectURI: redirectURI}
	var responseDto dto.SocialConsentResponse
	return httputil.EncodeResponse(ctx, responseModel, &responseDto)
}

// providerDisplayName returns the user-facing name for a provider, falling back
// to the provider identifier when it is not enabled or has no display name.
func (a *API) providerDisplayName(ctx httputil.RequestContext, providerName string) string {
	if a.providerStore == nil {
		return providerName
	}
	p, err := a.providerStore.GetProvider(providerName)
	if err != nil {
		return providerName
	}
	return p.DisplayName()
}

// verifySameOrigin guards the consent POST against CSRF. The consent page
// submits with a same-origin fetch carrying credentials, so a genuine approval
// always carries an Origin matching the host the page was served from — the
// API subdomain (e.g. account.example.com), not the bare core domain.
// A cross-site request cannot set the Origin header to the victim's host.
//
// When a client strips Origin (privacy modes, some webviews), it falls back to
// the Sec-Fetch-Site fetch-metadata header set by the same browser engine: a
// genuine fetch from the consent page is "same-origin", and "none" is a
// direct, user-initiated request. Anything else (cross-site, same-site
// sibling, opaque "null" origin, absent) fails closed.
func (a *API) verifySameOrigin() echo.MiddlewareFunc {
	// Resolve the API host once: the OAuth flow routes are served from the
	// dashboard API subdomain (see provider/setup.go callbackURL).
	apiHost := a.http.APISubdomain(a.Name(), true)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if origin := c.Request().Header.Get("Origin"); origin != "" {
				if sameOriginHost(apiHost, origin) {
					return next(c)
				}
				return echo.NewHTTPError(http.StatusForbidden, "cross-origin request rejected")
			}
			switch c.Request().Header.Get("Sec-Fetch-Site") {
			case "same-origin", "none":
				return next(c)
			default:
				return echo.NewHTTPError(http.StatusForbidden, "cross-origin request rejected")
			}
		}
	}
}

// sameOriginHost reports whether origin matches the expected host. The Origin
// header is always absolute (scheme://host); the expected host may not carry a
// scheme. Scheme is compared only when both are present; ports are ignored so
// the check is purely by hostname.
func sameOriginHost(expected, origin string) bool {
	o, err := url.Parse(origin)
	if err != nil || o.Hostname() == "" {
		return false
	}
	if strings.Contains(expected, "://") {
		d, err := url.Parse(expected)
		if err != nil {
			return false
		}
		return d.Hostname() == o.Hostname()
	}
	return expected == o.Hostname()
}

// loginRedirectURI establishes a session for the user and returns the
// auth-complete URL to navigate to. It does not write a response, so callers
// can either redirect (browser navigation) or return the URL as JSON.
func (a *API) loginRedirectURI(ctx httputil.RequestContext, userID uint, returnUrl string) (string, error) {
	_jwt, err := a.auth.LoginID(ctx.Request().Context(), userID, ctx.RealIP(), false)
	if err != nil {
		return "", err
	}

	return a.buildAuthCompleteURL(_jwt, returnUrl), nil
}

// loginAndRedirect establishes a session for the user and redirects to the
// auth-complete endpoint. Only reached from browser flows, so failures render
// the sign-in error screen.
func (a *API) loginAndRedirect(ctx httputil.RequestContext, providerName string, userID uint, returnUrl string) error {
	redirectURL, err := a.loginRedirectURI(ctx, userID, returnUrl)
	if err != nil {
		return a.socialErrorPage(ctx, providerName, err)
	}

	http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
	return nil
}

// socialConsentPath is the consent page path for a provider, relative to the
// API subdomain both the callback and the consent page are served from.
func socialConsentPath(providerName string) string {
	return fmt.Sprintf("/api/account/auth/sso/%s/consent", providerName)
}

// socialErrorPage renders the user-facing sign-in error screen that replaces
// raw JSON error bodies across the browser-driven OAuth callback flow. The
// mapped HTTP status is preserved, but the body is always a styled HTML page
// that never echoes provider, token, or internal error details — those stay
// in the server log (see the exchange-failure logging in socialAuthCallback).
// Known account conflicts (email already in use, provider already linked to
// another account) get specific, actionable copy; everything else gets a
// generic message.
func (a *API) socialErrorPage(ctx httputil.RequestContext, providerName string, err error) error {
	displayName := a.providerDisplayName(ctx, providerName)
	heading := "Sign-in could not be completed"
	message := "Something went wrong signing in with " + displayName +
		". Please try again or use another sign-in method."

	status := http.StatusInternalServerError
	var httpStatuser interface{ HttpStatus() int }

	switch {
	case errors.As(err, &httpStatuser):
		status = httpStatuser.HttpStatus()
	}

	acctErr := core.AsAccountError(err)
	if acctErr != nil {
		switch {
		case acctErr.IsErrorType(core.ErrKeySocialEmailConflict):
			heading = "Email already in use"
			message = "The email on your " + displayName + " account is already " +
				"associated with another account. Sign in with that account and " +
				"link " + displayName + " from your account settings."
		case acctErr.IsErrorType(core.ErrKeySocialAlreadyLinked):
			heading = "Account already linked"
			message = "This " + displayName + " account is already linked to " +
				"another account."
		}
	}

	responseHeader := ctx.Response().Header()
	responseHeader.Set("Content-Type", "text/html; charset=utf-8")
	ctx.Response().WriteHeader(status)
	return socialErrorTemplate.ExecuteTemplate(ctx.Response().Writer, "error", socialLayoutData{
		AriaLabelledBy:  "error-heading",
		AriaDescribedBy: "error-description",
		MetaDescription: "Sign-in error",
		PageData: socialErrorPageData{
			Heading:     heading,
			Message:     message,
			ActionURL:   "/",
			ActionLabel: "Back to sign in",
		},
	})
}

// socialError maps an account error to its HTTP status, else a 500.
// Only for API endpoints called by non-browser clients (consent submit fetch);
// browser-driven flows must use socialErrorPage instead.
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
	ctx := httputil.Context(c)

	if a.socialProvider == nil {
		apiErr := NewError(ErrKeyProviderListFailed, nil)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	configs, err := a.socialProvider.ListEnabled(ctx.Request().Context())
	if err != nil {
		apiErr := NewError(ErrKeyProviderListFailed, err)
		return ctx.Error(apiErr, apiErr.HttpStatus())
	}

	providers := lo.Map(configs, func(cfg *pluginDb.SocialProviderConfig, _ int) dto.PublicProviderResponse {
		return dto.PublicProviderResponse{
			ProviderID:  cfg.ProviderID,
			DisplayName: cfg.DisplayName,
			OrderIndex:  cfg.OrderIndex,
		}
	})

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
