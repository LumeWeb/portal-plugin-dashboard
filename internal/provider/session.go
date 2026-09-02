package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.lumeweb.com/portal-middleware/auth/adapter"
)

const (
	// SessionCookieName is the cookie used to carry the OAuth state + PKCE
	// verifier between the login redirect and the callback.
	SessionCookieName = "social_auth_session"

	// SessionMaxAge bounds how long a redirect/callback session is valid.
	SessionMaxAge = 5 * time.Minute
)

// Session modes distinguishing a login redirect from an authenticated link and
// from a pending verified-email link awaiting user consent.
const (
	SessionModeLogin       = "login"
	SessionModeLink        = "link"
	SessionModeConsentLink = "consent_link"
)

// SocialAuthSession is the minimal state held between the login redirect and
// the callback. It is signed (HMAC) and stored in a cookie.
type SocialAuthSession struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	ReturnURL    string `json:"return_url"`
	// Mode distinguishes login vs link vs consent link. Empty defaults to login.
	Mode string `json:"mode,omitempty"`
	// UserID is set for link mode: the authenticated user the provider is being
	// linked to.
	UserID uint `json:"user_id,omitempty"`
	// ProviderName, ProviderUserID, and Email carry the provider identity that
	// is awaiting user consent before it is linked into an existing account
	// (consent_link mode, entered from a login email-conflict).
	ProviderName   string `json:"provider_name,omitempty"`
	ProviderUserID string `json:"provider_user_id,omitempty"`
	Email          string `json:"email,omitempty"`
}

// SaveSession signs the session and stores it as a cookie.
func SaveSession(w http.ResponseWriter, session *SocialAuthSession, key []byte, cs adapter.CookieSetter, domain string) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	msg := base64.RawURLEncoding.EncodeToString(payload)
	sig := signSession(key, msg)

	cs.SetCookie(
		w,
		SessionCookieName,
		msg+"."+sig,
		domain,
		"/",
		time.Now().Add(SessionMaxAge),
		true,
		true,
		http.SameSiteLaxMode,
	)
	return nil
}

// GetSession reads, verifies, and decodes the session cookie.
func GetSession(r *http.Request, key []byte) (*SocialAuthSession, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie: %w", err)
	}

	msg, sig, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return nil, errors.New("malformed session cookie")
	}

	if !hmac.Equal([]byte(sig), []byte(signSession(key, msg))) {
		return nil, errors.New("invalid session signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(msg)
	if err != nil {
		return nil, fmt.Errorf("decode session: %w", err)
	}

	var session SocialAuthSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &session, nil
}

// ClearSession expires the session cookie.
func ClearSession(w http.ResponseWriter, cs adapter.CookieSetter, domain string) {
	cs.SetCookie(
		w,
		SessionCookieName,
		"",
		domain,
		"/",
		time.Unix(1, 0),
		true,
		true,
		http.SameSiteLaxMode,
	)
}

func signSession(key []byte, msg string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
