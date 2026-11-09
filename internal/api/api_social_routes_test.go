package api

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
)

func TestSocialRoutes_RegisterManagementPermissions(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api := core.GetAPI(internal.PLUGIN_NAME).(*API)
		access := mocks.NewMockAccessService(t)
		old := api.access
		api.access = access
		t.Cleanup(func() { api.access = old })
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/api/account/auth/links"},
			{http.MethodPost, "/api/account/auth/sso/:provider/link"},
			{http.MethodDelete, "/api/account/auth/sso/:provider"},
		} {
			access.EXPECT().RegisterRoute(mock.Anything, "account", route.path, route.method, core.ACCESS_USER_ROLE).Return(nil).Once()
		}
		r, err := router.NewRouter(router.APIInfo().Title("Social test").Version("1.0.0"))
		require.NoError(t, err)
		passthrough := func(next echo.HandlerFunc) echo.HandlerFunc { return next }
		require.NoError(t, api.setupSocialAuthRoutes(r, passthrough, passthrough))
	})
}
