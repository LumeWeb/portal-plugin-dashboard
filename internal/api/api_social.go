package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/sethvargo/go-password/password"
	"go.lumeweb.com/httputil"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
)

func (a *API) buildSocialAuthRoutes() []router.Route {
	return []router.Route{
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
	}
}

func (a *API) setupSocialAuthRoutes(gRouter router.Router) error {
	socialAuthRoutes := a.buildSocialAuthRoutes()

	if err := router.RegisterRoutes(gRouter, nil, a.Subdomain(), socialAuthRoutes); err != nil {
		return fmt.Errorf("failed to register social auth routes: %w", err)
	}

	return nil
}

func (a *API) socialAuthLogin(c echo.Context) error {
	ctx := httputil.Context(c)

	returnUrl := c.QueryParam(returnSessionKey)

	if !a.isValidReturnURL(returnUrl) {
		return ctx.Error(errors.New("invalid return URL"), http.StatusBadRequest)
	}

	err := gothic.StoreInSession(returnSessionKey, returnUrl, c.Request(), c.Response())
	if err != nil {
		return ctx.Error(err, http.StatusInternalServerError)
	}

	if gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request()); err == nil {
		a.setupOrLoginSocialUser(&gothUser, ctx, returnUrl)
		return nil
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

	if !a.isValidReturnURL(returnUrl) {
		return ctx.Error(errors.New("invalid return URL"), http.StatusBadRequest)
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
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			_ = ctx.Error(acctErr, acctErr.HttpStatus())
			return
		}
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
			if core.IsAccountError(err) {
				acctErr := core.AsAccountError(err)
				_ = ctx.Error(acctErr, acctErr.HttpStatus())
				return
			}
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}

		// Use names from the social profile
		err = a.user.UpdateAccountName(user.ID, guser.FirstName, guser.LastName)
		if err != nil {
			if core.IsAccountError(err) {
				acctErr := core.AsAccountError(err)
				_ = ctx.Error(acctErr, acctErr.HttpStatus())
				return
			}
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}

		// Ensure subsequent login uses the newly created account
		m = user
	}

	_jwt, err := a.auth.LoginID(m.ID, ctx.RealIP(), false)
	if err != nil {
		if core.IsAccountError(err) {
			acctErr := core.AsAccountError(err)
			_ = ctx.Error(acctErr, acctErr.HttpStatus())
			return
		}
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	redirectURL := a.buildAuthCompleteURL(_jwt, returnUrl)

	http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
}

// isValidReturnURL checks if a return URL is a same-site relative path
// Returns true for paths starting with "/" but not "//", false for empty or absolute URLs
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
