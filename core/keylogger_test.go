package service_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	pluginCore "go.lumeweb.com/portal-plugin-dashboard/core"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestAPIKeyUsageLogger_RecordsOnAPIPurpose(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeySvc)

		keyID := uuid.New()
		base := &gjwt.RegisteredClaims{Subject: "42", ID: keyID.String()}

		apiKeySvc.On("RecordAPIKeyUsage", mock.Anything, uint(42), keyID).Return(nil).Once()

		logger := pluginCore.NewAPIKeyUsageLogger(ctx)
		c := newEchoContext()
		logger.RecordAccess(c, "token", jwt.PurposeAPI, base, nil)

		apiKeySvc.AssertExpectations(tb)
	})
}

func TestAPIKeyUsageLogger_IgnoresNonAPIAndFailures(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		apiKeySvc := core.GetService[*pluginCore.MockAPIKeyService](ctx, pluginCore.API_KEY_SERVICE)
		require.NotNil(tb, apiKeySvc)

		logger := pluginCore.NewAPIKeyUsageLogger(ctx)
		c := newEchoContext()
		base := &gjwt.RegisteredClaims{Subject: "42", ID: uuid.New().String()}

		// Non-API purpose must be ignored.
		logger.RecordAccess(c, "token", jwt.PurposeLogin, base, nil)
		// Validation failure must be ignored.
		logger.RecordAccess(c, "token", jwt.PurposeAPI, base, assert.AnError)
		// Nil claims must be ignored.
		logger.RecordAccess(c, "token", jwt.PurposeAPI, nil, nil)
		// Wrong claims type must be ignored.
		logger.RecordAccess(c, "token", jwt.PurposeAPI, gjwt.MapClaims{"sub": "42"}, nil)
		// Malformed subject must be ignored.
		logger.RecordAccess(c, "token", jwt.PurposeAPI, &gjwt.RegisteredClaims{Subject: "not-a-number", ID: uuid.New().String()}, nil)
		// Malformed key id must be ignored.
		logger.RecordAccess(c, "token", jwt.PurposeAPI, &gjwt.RegisteredClaims{Subject: "42", ID: "not-a-uuid"}, nil)

		apiKeySvc.AssertNotCalled(tb, "RecordAPIKeyUsage", mock.Anything, mock.Anything, mock.Anything)
	})
}

func newEchoContext() echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}
