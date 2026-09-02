package dto

import (
	"time"

	"go.lumeweb.com/httputil"
)

// SocialAccountResponse is the public representation of a linked social
// account on the user's account.
type SocialAccountResponse struct {
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email"`
	CreatedAt      time.Time `json:"created_at"`
}

// SocialLoginQuery binds the query parameters for the social login redirect.
type SocialLoginQuery struct {
	ReturnURL string `query:"return"`
}

var _ httputil.DTORequest[*SocialLoginQuery] = (*SocialLoginQuery)(nil)

// ToModel implements httputil.DTORequest, returning the query unchanged.
func (q *SocialLoginQuery) ToModel() (*SocialLoginQuery, error) {
	return q, nil
}

// SocialCallbackQuery binds the query parameters returned by the OAuth
// provider on the callback endpoint.
type SocialCallbackQuery struct {
	Code  string `query:"code"`
	State string `query:"state"`
	Error string `query:"error"`
}

var _ httputil.DTORequest[*SocialCallbackQuery] = (*SocialCallbackQuery)(nil)

// ToModel implements httputil.DTORequest, returning the query unchanged.
func (q *SocialCallbackQuery) ToModel() (*SocialCallbackQuery, error) {
	return q, nil
}

// SocialConsentRequest is the JSON body of the consent page approve/reject
// POST (approve=true links the pending identity; false clears it).
type SocialConsentRequest struct {
	Approve bool `json:"approve"`
}

var _ httputil.DTORequest[*SocialConsentRequest] = (*SocialConsentRequest)(nil)

// ToModel implements httputil.DTORequest, returning the request unchanged.
func (r *SocialConsentRequest) ToModel() (*SocialConsentRequest, error) {
	return r, nil
}

// SocialConsentResponse is the JSON body returned by the consent page
// approve/reject endpoint. It carries the redirect URI the page JS navigates
// to after the user decides.
type SocialConsentResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// FromModel implements httputil.DTOResponse, mapping from another instance of
// the same DTO (key_identity pattern for DTO-only responses).
func (r *SocialConsentResponse) FromModel(model *SocialConsentResponse) error {
	r.RedirectURI = model.RedirectURI
	return nil
}
