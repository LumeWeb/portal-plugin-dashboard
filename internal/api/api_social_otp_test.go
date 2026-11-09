package api

import (
	"encoding/json"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/dto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

func TestFinishSocialLogin_OTPDoesNotIssueLoginSession(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, social := socialTestAPI(ctx)
		user := &models.User{Model: gorm.Model{ID: 7}, Email: "user@example.com", OTPEnabled: true, Verified: true}
		social.EXPECT().LoginOrLink(mock.Anything, "google", "uid-1", user.Email, true).Return(&core.SocialAuthResult{User: user, EmailVerified: true}, nil).Once()
		auth := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		// Allow the vulnerable implementation to complete so the redirect assertion exposes it.
		auth.EXPECT().LoginID(mock.Anything, uint(7), mock.Anything, false).Return(CreateTestLoginToken(tb, ctx, "7"), nil).Maybe()
		coreTesting.GetMockUserService(ctx).EXPECT().IsAccountPendingDeletion(mock.Anything, uint(7)).Return(false, nil).Maybe()
		c, w := newSocialTestContext(t)
		target := "/?to=https%3A%2F%2Fapp.example.com%2Fcallback%3Fx%3D1"
		require.NoError(tb, api.finishSocialLogin(c, "google", &provider.OAuth2User{ProviderUserID: "uid-1", Email: user.Email, EmailVerified: true}, target))
		require.Equal(tb, http.StatusFound, w.Code)
		require.Equal(tb, "/otp?to="+url.QueryEscape(target), w.Header().Get("Location"))
		auth.AssertNotCalled(tb, "LoginID")
		var challenge string
		for _, cookie := range w.Result().Cookies() {
			if cookie.Value == "" {
				continue
			}
			claims := &gjwt.RegisteredClaims{}
			_, err := gjwt.ParseWithClaims(cookie.Value, claims, func(*gjwt.Token) (any, error) { return ctx.Config().Config().Core.Identity.PublicKey(), nil }, gjwt.WithAudience("2fa"), gjwt.WithExpirationRequired())
			if err == nil {
				require.Equal(tb, "7", claims.Subject)
				require.LessOrEqual(tb, time.Until(claims.ExpiresAt.Time), 5*time.Minute)
				challenge = cookie.Value
			}
		}
		require.NotEmpty(tb, challenge, "response must set a short-lived 2FA cookie")
		pendingCookies := w.Result().Cookies()
		ping := httptest.NewRequest(http.MethodPost, "/api/auth/ping", nil)
		ping.Host = core.GetService[core.HTTPService](ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, false)
		for _, cookie := range pendingCookies {
			ping.AddCookie(cookie)
		}
		pingResponse := httptest.NewRecorder()
		ctx.Router().ServeHTTP(pingResponse, ping)
		require.Equal(tb, http.StatusUnauthorized, pingResponse.Code)

		loginToken := CreateTestLoginToken(tb, ctx, "7")
		auth.EXPECT().LoginOTP(mock.Anything, uint(7), "123456", false).Return(loginToken, nil).Once()
		validate := httptest.NewRequest(http.MethodPost, "/api/auth/otp/validate", strings.NewReader(`{"otp":"123456"}`))
		validate.Host = ping.Host
		validate.Header.Set("Content-Type", "application/json")
		for _, cookie := range pendingCookies {
			validate.AddCookie(cookie)
		}
		validated := httptest.NewRecorder()
		ctx.Router().ServeHTTP(validated, validate)
		require.Equal(tb, http.StatusOK, validated.Code)
		var result dto.LoginResponse
		require.NoError(tb, json.Unmarshal(validated.Body.Bytes(), &result))
		require.Equal(tb, loginToken, result.Token)
		require.False(tb, result.Otp)

	}, socialTestOptions)
}
