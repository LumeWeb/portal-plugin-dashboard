package api

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

// CreateTestJWTToken generates a valid JWT token for testing purposes
func CreateTestJWTToken(tb testing.TB, ctx coreTesting.TestContext, userID string, purpose jwt.Purpose) string {
	// Create valid JWT token using the context's identity
	pk := ctx.Config().Config().Core.Identity.PrivateKey()
	jwtToken, err := jwt.CreateToken(pk, ctx.Config().Config().Core.Domain, userID, purpose, 90*24*time.Hour)
	require.NoError(tb, err, "Failed to generate test JWT")
	return jwtToken
}

// CreateTestLoginToken generates a valid JWT token with login purpose for testing
func CreateTestLoginToken(tb testing.TB, ctx coreTesting.TestContext, userID string) string {
	return CreateTestJWTToken(tb, ctx, userID, jwt.PurposeLogin)
}

// CreateTest2FAToken generates a valid JWT token with 2FA purpose for testing
func CreateTest2FAToken(tb testing.TB, ctx coreTesting.TestContext, userID string) string {
	return CreateTestJWTToken(tb, ctx, userID, jwt.Purpose2FA)
}

// GenerateTestOTPSecret generates a test OTP secret using the core TOTPGenerate function
func GenerateTestOTPSecret(tb testing.TB) string {
	secret, err := core.TOTPGenerate("test-domain", "test@example.com")
	require.NoError(tb, err, "Failed to generate test OTP secret")
	return secret
}

// GenerateTestTOTPCode generates a valid TOTP code for the given secret
func GenerateTestTOTPCode(tb testing.TB, secret string) string {
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(tb, err, "Failed to generate test TOTP code")
	return code
}
