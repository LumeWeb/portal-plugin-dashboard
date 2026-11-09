package provider

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetSession_RejectsMissingOrExpiredDeadline(t *testing.T) {
	for _, deadline := range []int64{0, time.Now().Add(-time.Minute).Unix()} {
		payload, err := json.Marshal(map[string]any{"state": "state", "expires_at": deadline})
		require.NoError(t, err)
		msg := base64.RawURLEncoding.EncodeToString(payload)
		key := []byte("test-session-key")
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: msg + "." + signSession(key, msg)})
		_, err = GetSession(req, key)
		require.Error(t, err)
	}
}
