package api

import (
	"encoding/json"
	"net/http"

	core "go.lumeweb.com/portal/core"
)

// Error namespace for the dashboard social login + admin provider APIs. Keys
// follow the portal framework error registry pattern (portal-plugin-quota),
// so HTTP status codes live in one place and responses marshal to the
// canonical {"error":{"reason","details"}} body.
const Namespace = "dashboard.social"

const (
	ErrKeyInternalError          core.ErrorType = "INTERNAL_ERROR"
	ErrKeyInvalidRequest         core.ErrorType = "INVALID_REQUEST"
	ErrKeyInvalidReturnURL       core.ErrorType = "INVALID_RETURN_URL"
	ErrKeyInvalidState           core.ErrorType = "INVALID_STATE"
	ErrKeyProviderError          core.ErrorType = "PROVIDER_ERROR"
	ErrKeyMissingAuthCode        core.ErrorType = "MISSING_AUTH_CODE"
	ErrKeyInvalidLinkSession     core.ErrorType = "INVALID_LINK_SESSION"
	ErrKeyInvalidConsentSession  core.ErrorType = "INVALID_CONSENT_SESSION"
	ErrKeyProviderNotEnabled     core.ErrorType = "PROVIDER_NOT_ENABLED"
	ErrKeyProviderNotFound       core.ErrorType = "PROVIDER_NOT_FOUND"
	ErrKeyProviderDuplicate      core.ErrorType = "PROVIDER_DUPLICATE"
	ErrKeyProviderFetchFailed    core.ErrorType = "PROVIDER_FETCH_FAILED"
	ErrKeyProviderCreateFailed   core.ErrorType = "PROVIDER_CREATE_FAILED"
	ErrKeyProviderUpdateFailed   core.ErrorType = "PROVIDER_UPDATE_FAILED"
	ErrKeyProviderDeleteFailed   core.ErrorType = "PROVIDER_DELETE_FAILED"
	ErrKeyProviderListFailed     core.ErrorType = "PROVIDER_LIST_FAILED"
	ErrKeyProviderExchangeFailed core.ErrorType = "PROVIDER_EXCHANGE_FAILED"
	ErrKeyProviderCacheReload    core.ErrorType = "PROVIDER_CACHE_RELOAD_FAILED"
)

func init() {
	core.MustRegisterNamespace(Namespace)
	core.MustRegisterDefaultErrorMessages(Namespace, map[core.ErrorType]core.ErrorDefinition{
		ErrKeyInternalError:          {Key: ErrKeyInternalError, Message: "An internal error occurred."},
		ErrKeyInvalidRequest:         {Key: ErrKeyInvalidRequest, Message: "Invalid request."},
		ErrKeyInvalidReturnURL:       {Key: ErrKeyInvalidReturnURL, Message: "Invalid return URL."},
		ErrKeyInvalidState:           {Key: ErrKeyInvalidState, Message: "Invalid or mismatched state parameter."},
		ErrKeyProviderError:          {Key: ErrKeyProviderError, Message: "The provider returned an error."},
		ErrKeyMissingAuthCode:        {Key: ErrKeyMissingAuthCode, Message: "Missing authorization code."},
		ErrKeyInvalidLinkSession:     {Key: ErrKeyInvalidLinkSession, Message: "Invalid link session."},
		ErrKeyInvalidConsentSession:  {Key: ErrKeyInvalidConsentSession, Message: "Invalid or expired consent session."},
		ErrKeyProviderNotEnabled:     {Key: ErrKeyProviderNotEnabled, Message: "Provider is not enabled."},
		ErrKeyProviderNotFound:       {Key: ErrKeyProviderNotFound, Message: "Provider not found."},
		ErrKeyProviderFetchFailed:    {Key: ErrKeyProviderFetchFailed, Message: "Failed to fetch provider."},
		ErrKeyProviderDuplicate:      {Key: ErrKeyProviderDuplicate, Message: "A provider with this identifier already exists."},
		ErrKeyProviderCreateFailed:   {Key: ErrKeyProviderCreateFailed, Message: "Failed to create provider."},
		ErrKeyProviderUpdateFailed:   {Key: ErrKeyProviderUpdateFailed, Message: "Failed to update provider."},
		ErrKeyProviderDeleteFailed:   {Key: ErrKeyProviderDeleteFailed, Message: "Failed to delete provider."},
		ErrKeyProviderListFailed:     {Key: ErrKeyProviderListFailed, Message: "Failed to list providers."},
		ErrKeyProviderExchangeFailed: {Key: ErrKeyProviderExchangeFailed, Message: "Failed to exchange the authorization code."},
		ErrKeyProviderCacheReload:    {Key: ErrKeyProviderCacheReload, Message: "Provider saved but the live cache reload failed."},
	})

	core.MustRegisterErrorCodes(Namespace, map[core.ErrorType]int{
		ErrKeyInternalError:          http.StatusInternalServerError,
		ErrKeyInvalidRequest:         http.StatusBadRequest,
		ErrKeyInvalidReturnURL:       http.StatusBadRequest,
		ErrKeyInvalidState:           http.StatusBadRequest,
		ErrKeyProviderError:          http.StatusBadRequest,
		ErrKeyMissingAuthCode:        http.StatusBadRequest,
		ErrKeyInvalidLinkSession:     http.StatusBadRequest,
		ErrKeyInvalidConsentSession:  http.StatusBadRequest,
		ErrKeyProviderNotEnabled:     http.StatusBadRequest,
		ErrKeyProviderNotFound:       http.StatusNotFound,
		ErrKeyProviderFetchFailed:    http.StatusInternalServerError,
		ErrKeyProviderDuplicate:      http.StatusConflict,
		ErrKeyProviderCreateFailed:   http.StatusInternalServerError,
		ErrKeyProviderUpdateFailed:   http.StatusInternalServerError,
		ErrKeyProviderDeleteFailed:   http.StatusInternalServerError,
		ErrKeyProviderListFailed:     http.StatusInternalServerError,
		ErrKeyProviderExchangeFailed: http.StatusInternalServerError,
		ErrKeyProviderCacheReload:    http.StatusInternalServerError,
	})
}

// SocialError is the plugin error type implementing the framework's
// router.ResponseError + json.Marshaler contracts.
type SocialError struct {
	err *core.Error
}

func (e *SocialError) Error() string   { return e.err.Error() }
func (e *SocialError) HttpStatus() int { return e.err.HttpStatus() }
func (e *SocialError) Unwrap() error   { return e.err }

// MarshalJSON serializes to the canonical {"error":{"reason","details"}} body.
func (e *SocialError) MarshalJSON() ([]byte, error) {
	if e == nil || e.err == nil {
		return json.Marshal(map[string]any{"error": map[string]any{"reason": "Unknown"}})
	}
	return e.err.MarshalJSON()
}

// NewError builds a framework error in this namespace.
func NewError(key core.ErrorType, err error, args ...any) *SocialError {
	return &SocialError{err: core.NewError(Namespace, key, err, args...)}
}
