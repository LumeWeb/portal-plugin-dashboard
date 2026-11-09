package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOTPValidateSwagger_DocumentsJSONAndRedirect(t *testing.T) {
	for _, route := range (&API{}).buildOTPRoutes(nil, nil, nil) {
		if route.Path != "/api/auth/otp/validate" || route.Method != http.MethodPost {
			continue
		}
		require.Contains(t, route.Swagger.Responses, http.StatusOK)
		require.Contains(t, route.Swagger.Responses, http.StatusFound)
		require.Contains(t, route.Swagger.Responses[http.StatusFound].Headers, "Location")
		require.Contains(t, route.Swagger.Responses, http.StatusUnauthorized)
		return
	}
	t.Fatal("OTP validation route missing")
}
