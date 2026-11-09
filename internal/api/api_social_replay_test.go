package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestSocialConsentSubmit_RejectConsumesRetainedCookie(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, _ := socialTestAPI(ctx)
		consentSession(tb, api, provider.SocialAuthSession{Mode: provider.SessionModeConsentLink, ProviderName: "google", ProviderUserID: "uid-3", Email: "taken@example.com"}, func(cookies []*http.Cookie) {
			for i, want := range []int{http.StatusOK, http.StatusBadRequest} {
				req := httptest.NewRequest(http.MethodPost, "/api/account/auth/sso/google/consent", strings.NewReader(`{"approve":false}`))
				req.Header.Set("Content-Type", "application/json")
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				c := echo.New().NewContext(req, w)
				c.SetParamNames("provider")
				c.SetParamValues("google")
				require.NoError(tb, api.socialConsentSubmit(c))
				require.Equal(tb, want, w.Code, "submission %d", i+1)
			}
		})
	}, socialTestOptions)
}
