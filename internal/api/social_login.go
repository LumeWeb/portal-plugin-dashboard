package api

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
)

// loginRedirectURI completes the verified social primary factor. LoginID skips
// OTP, so accounts with OTP receive only a challenge until LoginOTP succeeds.
func (a *API) loginRedirectURI(ctx httputil.RequestContext, user *models.User, returnURL string) (string, error) {
	if user == nil || user.ID == 0 {
		return "", core.NewAccountError(core.ErrKeyInvalidLogin, nil)
	}
	if user.OTPEnabled {
		pending, err := a.user.IsAccountPendingDeletion(ctx.Request().Context(), user.ID)
		if err != nil {
			return "", err
		}
		if pending {
			return "", core.NewAccountError(core.ErrKeyAccountPendingDeletion, nil)
		}
		cfg := a.Config().Config().Core
		token, err := jwt.CreateToken(cfg.Identity.PrivateKey(), cfg.Domain, strconv.FormatUint(uint64(user.ID), 10), jwt.Purpose2FA, 5*time.Minute)
		if err != nil {
			return "", err
		}
		if err := a.setAuthCookieWithRemember(ctx.Context, token, false); err != nil {
			return "", err
		}
		a.storeRememberFlagInCookie(ctx.Context, false)
		if returnURL == "" {
			returnURL = "/"
		}
		return "/otp?to=" + url.QueryEscape(returnURL), nil
	}
	token, err := a.auth.LoginID(ctx.Request().Context(), user.ID, ctx.RealIP(), false)
	if err != nil {
		return "", err
	}
	return a.buildAuthCompleteURL(token, returnURL), nil
}

// loginAndRedirect is the browser-navigation form of social login completion.
func (a *API) loginAndRedirect(ctx httputil.RequestContext, providerName string, user *models.User, returnURL string) error {
	redirectURL, err := a.loginRedirectURI(ctx, user, returnURL)
	if err != nil {
		return a.socialErrorPage(ctx, providerName, err)
	}
	http.Redirect(ctx.Response(), ctx.Request(), redirectURL, http.StatusFound)
	return nil
}
