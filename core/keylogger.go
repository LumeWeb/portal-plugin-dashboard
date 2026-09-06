// Package service provides the API key logging helper that other plugins wire
// into portal-middleware's authentication middleware (portal-middleware v0.3.8+,
// auth.JWTKeyLogger hook). Usage:
//
//	mw := middleware.AuthMiddleware(ctx,
//	    middleware.WithAuthPurpose(jwt.PurposeAPI),
//	    pluginCore.WithAPIKeyUsageLogging(ctx),
//	)
package service

import (
	"strconv"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	"go.lumeweb.com/portal/core"
	"go.uber.org/zap"
)

// WithAPIKeyUsageLogging is the single middleware option that records API key
// usage. Any plugin route protected with a purpose-"api" auth middleware
// automatically refreshes the used key's last-used timestamp.
func WithAPIKeyUsageLogging(ctx core.Context) middleware.AuthOption {
	return middleware.WithAuthKeyLogger(NewAPIKeyUsageLogger(ctx))
}

// NewAPIKeyUsageLogger adapts the APIKeyService into a portal-middleware
// JWTKeyLogger. Only successful purpose-"api" tokens are recorded; failures,
// missing claims, and unparseable subject/key IDs are ignored so logging can
// never reject a request that the middleware already accepted. The underlying
// service resolves via GetServiceOptional, so the middleware stays a no-op
// when the dashboard plugin is not loaded.
func NewAPIKeyUsageLogger(ctx core.Context) auth.JWTKeyLogger {
	return &apiKeyUsageLogger{ctx: ctx}
}

type apiKeyUsageLogger struct {
	ctx core.Context
}

// RecordAccess implements auth.JWTKeyLogger. The middleware recovers panics,
// but this implementation is deliberately panic-free and swallows all errors.
func (l *apiKeyUsageLogger) RecordAccess(c echo.Context, _ string, purpose jwt.Purpose, claims gjwt.Claims, err error) {
	if err != nil || claims == nil || purpose != jwt.PurposeAPI {
		return
	}

	base, ok := claims.(*gjwt.RegisteredClaims)
	if !ok || base.Subject == "" || base.ID == "" {
		return
	}

	userID, err := strconv.ParseUint(base.Subject, 10, 64)
	if err != nil {
		return
	}
	keyID, err := uuid.Parse(base.ID)
	if err != nil {
		return
	}

	svc := core.GetServiceOptional[APIKeyService](l.ctx, API_KEY_SERVICE)
	if svc == nil {
		return // no-op when the dashboard plugin is not loaded
	}
	if err := svc.RecordAPIKeyUsage(c.Request().Context(), uint(userID), keyID); err != nil {
		l.ctx.Logger().Error("failed to record api key usage", zap.Error(err), zap.Uint64("user_id", userID))
	}
}
