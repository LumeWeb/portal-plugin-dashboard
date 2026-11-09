package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestParseAPIKeyToken_VerifiesCredential(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api := core.GetAPI(internal.PLUGIN_NAME).(*API)
		keyID := uuid.New()
		_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(tb, err)
		for _, name := range []string{"valid", "wrong signature", "unsigned", "wrong algorithm", "wrong issuer", "missing issuer", "wrong audience", "missing audience", "expired", "missing expiry", "future nbf", "zero user", "negative user", "overflow user", "invalid uuid", "zero uuid"} {
			t.Run(name, func(t *testing.T) {
				claims := gjwt.RegisteredClaims{Issuer: ctx.Config().Config().Core.Domain, Subject: "7", ID: keyID.String(), Audience: []string{"api"}, ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Hour))}
				method := gjwt.SigningMethod(gjwt.SigningMethodEdDSA)
				var signingKey any = ctx.Config().Config().Core.Identity.PrivateKey()
				switch name {
				case "wrong signature":
					signingKey = wrongKey
				case "unsigned":
					method = gjwt.SigningMethodNone
					signingKey = gjwt.UnsafeAllowNoneSignatureType
				case "wrong algorithm":
					method = gjwt.SigningMethodHS256
					signingKey = []byte("not-a-portal-key")
				case "wrong issuer":
					claims.Issuer = "other.example"
				case "missing issuer":
					claims.Issuer = ""
				case "wrong audience":
					claims.Audience = []string{"login"}
				case "missing audience":
					claims.Audience = nil
				case "expired":
					claims.ExpiresAt = gjwt.NewNumericDate(time.Now().Add(-time.Hour))
				case "missing expiry":
					claims.ExpiresAt = nil
				case "future nbf":
					claims.NotBefore = gjwt.NewNumericDate(time.Now().Add(time.Hour))
				case "zero user":
					claims.Subject = "0"
				case "negative user":
					claims.Subject = "-1"
				case "overflow user":
					claims.Subject = "18446744073709551616"
				case "invalid uuid":
					claims.ID = "bad"
				case "zero uuid":
					claims.ID = uuid.Nil.String()
				}
				token, err := gjwt.NewWithClaims(method, claims).SignedString(signingKey)
				require.NoError(t, err)
				req := httptest.NewRequest("POST", "/api/auth/key", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				c := httputil.Context(echo.New().NewContext(req, httptest.NewRecorder()))
				userID, parsedKey, err := api.parseAPIKeyToken(c)
				if name == "valid" {
					require.NoError(t, err)
					require.Equal(t, uint(7), userID)
					require.Equal(t, keyID, parsedKey)
				} else {
					require.Error(t, err)
				}
			})
		}
	})
}
